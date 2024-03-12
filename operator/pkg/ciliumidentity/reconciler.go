package ciliumidentity

import (
	"context"
	"fmt"
	"strconv"
	"time"

	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"

	"github.com/cilium/cilium/operator/pkg/ciliumendpointslice"
	"github.com/cilium/cilium/operator/watchers"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/identity/basicallocator"
	"github.com/cilium/cilium/pkg/identity/key"
	"github.com/cilium/cilium/pkg/idpool"
	"github.com/cilium/cilium/pkg/k8s"
	cilium_api_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

type reconciler struct {
	// Cilium kubernetes clients to access V2 and V2alpha1 resources
	clientset k8sClient.Clientset
	// Cache of Cilium Identities formed from kube-apiserver watcher.
	idAllocator        *basicallocator.BasicIDAllocator
	desiredCIDState    *CIDState
	cidUsageInPods     *CIDUsageInPods
	cidUsageInCES      *CIDUsageInCES
	cidDeletionTracker *CIDDeletionTracker
	queueOps           queueOperations

	// Ensures no CID duplicates are created while allocating CIDs in parallel.
	cidCreateLock lock.RWMutex

	cesEnabled bool

	googleMultiNICEnabled bool
	multiNICPods          *multiNICPods
}

func newReconciler(
	clientset k8sClient.Clientset,
	cesEnabled bool,
	googleMultiNICEnabled bool,
	queueOps queueOperations,
) *reconciler {
	log.Info("Creating Cilium Identity reconciler")

	minIDValue := idpool.ID(identity.MinimalAllocationIdentity)
	maxIDValue := idpool.ID(identity.MaximumAllocationIdentity)
	idAllocator := basicallocator.NewBasicIDAllocator(minIDValue, maxIDValue)

	r := &reconciler{
		clientset:             clientset,
		idAllocator:           idAllocator,
		desiredCIDState:       NewCIDState(),
		cidUsageInPods:        NewCIDUsageInPods(),
		cidUsageInCES:         NewCIDUsageInCES(),
		cidDeletionTracker:    NewCIDDeletionTracker(),
		queueOps:              queueOps,
		cesEnabled:            cesEnabled,
		googleMultiNICEnabled: googleMultiNICEnabled,
	}

	if r.googleMultiNICEnabled {
		r.multiNICPods = NewMultiNICPods()
	}

	return r
}

func (r *reconciler) calcDesiredStateOnStartup() error {
	r.syncCESsOnStartup()
	return r.syncPodsOnStartup()
}

func (r *reconciler) syncCESsOnStartup() {
	if !r.cesEnabled {
		return
	}

	for _, cesObj := range ciliumendpointslice.CESliceStore.List() {
		ces, ok := cesObj.(*v2alpha1.CiliumEndpointSlice)
		if !ok {
			continue
		}

		r.cidUsageInCES.ProcessCESUpsert(ces.Name, ces.Endpoints)
	}
}

// syncPodsOnStartup ensures that all pods have a CID for their labels, and that
// all non-used CIDs are deleted. Non used CIDs are those that aren't in use by
// any of the pods and also don't exist in CESs (if CES is enabled).
func (r *reconciler) syncPodsOnStartup() error {
	var lastError error

	for _, podObj := range watchers.PodStore.List() {
		pod, ok := podObj.(*slim_corev1.Pod)
		if !ok {
			continue
		}

		if err := r.reconcilePod(podResourceKey(pod.Name, pod.Namespace)); err != nil {
			lastError = err
		}
	}

	return lastError
}

// reconcileCID ensures that the desired state for the CID is reached, by
// comparing the CID in desired state cache and watcher's store and doing one of
// the following:
// 1. Nothing - If CID doesn't exist in both desired state cache and watcher's
// store.
// 2. Deletes CID - If CID only exists in the watcher's store and it isn't used.
// 3. Creates CID - If CID only exists in the desired state cache.
// 4. Updates CID - If CIDs in the desired state cache and watcher's store are
// not the same.
func (r *reconciler) reconcileCID(cidResourceKey resource.Key) error {
	cidName := cidResourceKey.Name
	storeCIDObj, existsInStore, err := watchers.CIDStore.GetByKey(cidResourceKey.Name)
	if err != nil && !k8serrors.IsNotFound(err) {
		return err
	}
	var storeCID *cilium_api_v2.CiliumIdentity
	if existsInStore {
		var ok bool
		storeCID, ok = storeCIDObj.(*cilium_api_v2.CiliumIdentity)
		if !ok {
			return fmt.Errorf("wrong type (%T) of object when getting CID %q from the CID watcher store", storeCIDObj, cidName)
		}
	}

	cidKey, existsInDesiredState := r.desiredCIDState.LookupByID(cidName)
	if !existsInDesiredState && !existsInStore {
		r.makeIDAvailable(cidName)
		return nil
	}

	cidIsUsed := r.cidIsUsedInPods(cidName) || r.cidIsUsedInCEPOrCES(cidName)
	if !existsInDesiredState {
		if cidIsUsed {
			return nil
		}
		return r.handleCIDDeletion(cidName)
	}

	if !cidIsUsed {
		// The CID shouldn't exist in the desired state because it isn't used.
		r.cleanUpCID(cidName)
		return nil
	}

	if !existsInStore {
		return r.createCID(cidName, cidKey)
	}

	storeCIDKey := key.GetCIDKeyFromSecurityLabels(storeCID.SecurityLabels)
	if cidKey.Equals(storeCIDKey.LabelArray) {
		return nil
	}

	return r.updateCID(storeCID, cidKey)
}

func (r *reconciler) createCID(cidName string, cidKey *key.GlobalIdentity) error {
	cidLabels := cidKey.GetAsMap()
	selectedLabels, skippedLabels := identity.SanitizeK8sLabels(cidLabels)
	log.WithField(logfields.Labels, skippedLabels).Debug("Skipped non-kubernetes labels when labelling ciliumidentity. All labels will still be used in identity determination")

	cid := &cilium_api_v2.CiliumIdentity{
		ObjectMeta: metav1.ObjectMeta{
			Name:   cidName,
			Labels: selectedLabels,
		},
		SecurityLabels: cidLabels,
	}

	log.WithField(logfields.CIDName, cidName).Infof("Creating a Cilium Identity for security labels: %+v", cidLabels)

	_, err := r.clientset.CiliumV2().CiliumIdentities().Create(context.TODO(), cid, metav1.CreateOptions{})
	return err
}

func (r *reconciler) updateCID(cid *cilium_api_v2.CiliumIdentity, cidKey *key.GlobalIdentity) error {
	cidLabels := cidKey.GetAsMap()
	selectedLabels, skippedLabels := identity.SanitizeK8sLabels(cidLabels)
	log.WithField(logfields.Labels, skippedLabels).Debug("Skipped non-kubernetes labels when labelling ciliumidentity. All labels will still be used in identity determination")

	cid.Labels = selectedLabels
	cid.SecurityLabels = cidLabels

	log.WithField(logfields.CIDName, cid.Name).Info("Updating a Cilium Identity")

	_, err := r.clientset.CiliumV2().CiliumIdentities().Update(context.TODO(), cid, metav1.UpdateOptions{})
	return err
}

func (r *reconciler) deleteCID(cidName string) error {
	log.WithField(logfields.CIDName, cidName).Info("Deleting a Cilium Identity")

	err := r.clientset.CiliumV2().CiliumIdentities().Delete(context.TODO(), cidName, metav1.DeleteOptions{})
	if err != nil {
		return err
	}

	r.makeIDAvailable(cidName)
	return nil
}

func (r *reconciler) handleCIDDeletion(cidName string) error {
	markedTime, isMarked := r.cidDeletionTracker.MarkedTime(cidName)
	if !isMarked {
		r.cidDeletionTracker.Mark(cidName)
		r.queueOps.enqueueCIDReconciliation(cidResourceKey(cidName), cidDeleteDelay)
		return nil
	}

	durationSinceMarked := time.Since(markedTime)
	if durationSinceMarked >= cidDeleteDelay {
		r.cidDeletionTracker.Unmark(cidName)
		return r.deleteCID(cidName)
	}

	r.queueOps.enqueueCIDReconciliation(cidResourceKey(cidName), cidDeleteDelay)
	return nil
}

func (r *reconciler) makeIDAvailable(cidName string) error {
	cidNum, err := strconv.Atoi(cidName)
	if err != nil {
		return err
	}
	return r.idAllocator.ReturnToAvailablePool(idpool.ID(cidNum))
}

func (r *reconciler) upsertDesiredState(cidName string, cidKey *key.GlobalIdentity) error {
	if cidKey == nil || len(cidName) == 0 {
		return fmt.Errorf("invalid CID, name: %q, key: %v", cidName, cidKey)
	}

	cachedCIDKey, exists := r.desiredCIDState.LookupByID(cidName)
	if exists && cidKey.Equals(cachedCIDKey.LabelArray) {
		return nil
	}

	id, err := r.idAllocator.ValidateIDString(cidName)
	if err != nil {
		return err
	}

	err = r.idAllocator.Allocate(idpool.ID(id))
	if err != nil {
		return err
	}
	r.desiredCIDState.Upsert(cidName, cidKey)

	return nil
}

// reconcilePod ensures that there is a CID that matches the pod. CIDs are
// created for new unique label sets, and potentailly deleted when pods are
// deleted, if no other pods match the CID labels.
func (r *reconciler) reconcilePod(podKey resource.Key) error {
	if r.googleMultiNICEnabled {
		return r.reconcileMultiNICPod(podKey)
	}

	podObj, exists, err := watchers.PodStore.GetByKey(podKey.String())
	if err != nil && !k8serrors.IsNotFound(err) {
		return err
	}
	// When a pod is not found in the pod store, it means it's deleted.
	if !exists {
		prevCIDName, count, found := r.cidUsageInPods.RemovePod(podKey.String())
		if found && count == 0 && !r.cidIsUsedInCEPOrCES(prevCIDName) {
			r.cleanUpCID(prevCIDName)
		}
		return nil
	}

	pod, ok := podObj.(*slim_corev1.Pod)
	if !ok {
		return fmt.Errorf("wrong type (%T) of object when getting Pod %q from the Pod watcher store", podObj, podKey.String())
	}

	cidName, err := r.allocateCIDForPod(pod)
	if err != nil {
		return err
	}

	prevCIDName, count := r.cidUsageInPods.AssignCIDToPod(podKey.String(), cidName)
	if len(prevCIDName) > 0 && count == 0 && !r.cidIsUsedInCEPOrCES(prevCIDName) {
		r.cleanUpCID(prevCIDName)
	}

	return nil
}

func (r *reconciler) cleanUpCID(cidName string) {
	r.desiredCIDState.Remove(cidName)
	r.queueOps.enqueueCIDReconciliation(cidResourceKey(cidName), 0)
}

func (r *reconciler) cidIsUsedInPods(cidName string) bool {
	return r.cidUsageInPods.CIDUsageCount(cidName) > 0
}

func (r *reconciler) cidIsUsedInCEPOrCES(cidName string) bool {
	if !r.cesEnabled {
		return watchers.HasCEWithIdentity(cidName)
	}

	cidUsageCount := r.cidUsageInCES.CIDUsageCount(cidName)
	return cidUsageCount > 0
}

// allocateCIDForPod gets pod and namespace labels that are relevant to security
// identities, and ensures that a CID exists for that label set.
// 1. CID exists: No action.
// 2. CID doesn't exist: Create CID.
func (r *reconciler) allocateCIDForPod(pod *slim_corev1.Pod) (string, error) {
	k8sLabels, err := r.getRelevantLabelsForPod(pod)
	if err != nil {
		return "", err
	}

	return r.allocateCID(k8sLabels)
}

func (r *reconciler) allocateCID(k8sLabels map[string]string) (string, error) {
	cidKey := key.GetCIDKeyFromK8sLabels(k8sLabels)
	r.cidCreateLock.Lock()
	defer r.cidCreateLock.Unlock()

	cidName, exists := r.desiredCIDState.LookupByKey(cidKey)
	if exists {
		return cidName, nil
	}

	storeCIDs, err := watchers.CIDStore.ByIndex(watchers.ByKeyIndex, cidKey.GetKey())
	if err != nil {
		return "", err
	}

	// If CIDs that match labels are found in CID watcher store but not in the
	// desired cache, they need to be added to the desired cache and used instead
	// of creating a new CID for these labels.
	if len(storeCIDs) > 0 {
		return r.handleStoreCIDMatch(storeCIDs)
	}

	allocatedID, err := r.idAllocator.AllocateRandom()
	if err != nil {
		return "", err
	}

	cidName = allocatedID.String()
	r.desiredCIDState.Upsert(cidName, cidKey)
	r.queueOps.enqueueCIDReconciliation(cidResourceKey(cidName), 0)

	return cidName, nil
}

func (r *reconciler) getRelevantLabelsForPod(pod *slim_corev1.Pod) (map[string]string, error) {
	ns, err := r.getNamespace(pod.Namespace)
	if err != nil {
		return nil, err
	}

	_, labelsMap, _, err := k8s.GetPodMetadata(ns, pod)
	if err != nil {
		return nil, err
	}

	return labelsMap, nil
}

func (r *reconciler) getNamespace(namespace string) (*slim_corev1.Namespace, error) {
	nsLookupObj := &slim_corev1.Namespace{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name: namespace,
		},
	}

	nsObj, exists, err := watchers.NSStore.Get(nsLookupObj)
	if err != nil {
		return nil, fmt.Errorf("unable to get namespace %q, error: %v", namespace, err)
	}
	if !exists {
		return nil, fmt.Errorf("namespace %q not found in store", namespace)
	}
	ns, ok := nsObj.(*slim_corev1.Namespace)
	if !ok {
		return nil, fmt.Errorf("wrong type (%T) of object when getting Namespace %q from the Namespace watcher store", nsObj, namespace)
	}

	return ns, nil
}

func (r *reconciler) handleStoreCIDMatch(storeCIDs []interface{}) (string, error) {
	if len(storeCIDs) == 0 {
		return "", fmt.Errorf("store CIDs list is empty")
	}

	var selectedCIDName string

	// Deduplication: Reconcile all CID. The first will be added to the desired
	// cache and the rest will be deleted, because they are not used.
	for _, cidObj := range storeCIDs {
		cid, err := convertObjToCID(cidObj)
		if err != nil {
			return "", err
		}

		toDelete := true

		if len(selectedCIDName) == 0 {
			cidKey := key.GetCIDKeyFromSecurityLabels(cid.SecurityLabels)
			if err := r.upsertDesiredState(cid.Name, cidKey); err != nil {
				log.Warningf("Failed to add CID %s to cache: %v", cid.Name, err)
			} else {
				toDelete = false
				selectedCIDName = cid.Name
			}
		}

		if toDelete {
			r.queueOps.enqueueCIDReconciliation(cidResourceKey(cid.Name), 0)
		}
	}

	return selectedCIDName, nil
}

func convertObjToCID(cidObj interface{}) (*cilium_api_v2.CiliumIdentity, error) {
	cid, ok := cidObj.(*cilium_api_v2.CiliumIdentity)
	if !ok {
		return cid, fmt.Errorf("wrong type (%T) of object when getting CID from the CID watcher store", cidObj)
	}
	return cid, nil
}

// reconcileNS enqueues all pods in the namespace to be reconciled by the CID
// controller.
func (r *reconciler) reconcileNS(nsKey resource.Key) error {
	if err := r.updateAllPodsInANS(nsKey.Name); err != nil {
		return fmt.Errorf("failed to reconcile namespace %s change: %v", nsKey.Name, err)
	}
	return nil
}

func (r *reconciler) updateAllPodsInANS(namespace string) error {
	log.Infof("Reconciling all pods in namespace %s", namespace)

	if watchers.PodStore == nil {
		return fmt.Errorf("pod store is not initialized")
	}
	podList, err := watchers.PodStore.(cache.Indexer).ByIndex(cache.NamespaceIndex, namespace)
	if err != nil {
		return err
	}

	var lastErr error

	for _, podObj := range podList {
		pod, ok := podObj.(*slim_corev1.Pod)
		if !ok {
			continue
		}

		r.queueOps.enqueuePodReconciliation(podResourceKey(pod.Name, pod.Namespace), 0)
	}

	return lastErr
}
