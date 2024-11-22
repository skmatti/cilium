package ciliumidentity

import (
	"fmt"
	"strings"

	networkv1 "github.com/GoogleCloudPlatform/gke-networking-api/apis/network/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"

	"github.com/cilium/cilium/pkg/identity/key"
	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

type mnLabels map[string]string

type mnPodCache map[string]bool

// multiNICPods is used to track multi network pods for deletion. Once pod is
// deleted, we need to know which multi network pods were used inside the CID
// controller, to clean up those identities.
type multiNICPods struct {
	mnPods map[string]mnPodCache
	mu     lock.RWMutex
}

func NewMultiNICPods() *multiNICPods {
	return &multiNICPods{
		mnPods: make(map[string]mnPodCache),
	}
}

func (m *multiNICPods) GetMNPodMap(podKey string) mnPodCache {
	m.mu.RLock()
	defer m.mu.RUnlock()

	mnPodMap := m.mnPods[podKey]
	return mnPodMap
}

func (m *multiNICPods) Add(podKey string, mnPodMap mnPodCache) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.mnPods[podKey] = mnPodMap
}

func (m *multiNICPods) Remove(podKey string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.mnPods, podKey)
}

// reconcileMultiNICPod treats every network interface as a separate pod.
func (r *reconciler) reconcileMultiNICPod(podKey resource.Key) error {
	if !r.googleMultiNICEnabled {
		return fmt.Errorf("google multi network is not enabled, but pod reconciliation for multi-network pod is called")
	}

	podFullName := podKey.String()

	pod, exists, err := r.podStore.GetByKey(podKey)
	if err != nil && !k8serrors.IsNotFound(err) {
		return err
	}
	// When a pod is not found in the pod store, it means it's deleted.
	if !exists {
		mnPodMap := r.multiNICPods.GetMNPodMap(podFullName)
		for mnPodName := range mnPodMap {
			_, _, _ = r.cidUsageInPods.RemovePod(mnPodName)
			// CID deletion is handled by identitygc
		}

		r.multiNICPods.Remove(podFullName)
		return nil
	}

	return r.allocateCIDForMultiNICPod(pod)
}

func (r *reconciler) allocateCIDForMultiNICPod(pod *slim_corev1.Pod) error {
	mnPods, err := r.getRelevantLabelsForMultiNICPod(pod)
	if err != nil {
		return fmt.Errorf("get relevant labels for multi-network pod: %v", err)
	}

	failedAllocations := 0
	mnPodMap := make(mnPodCache)

	r.cidCreateLock.Lock()
	defer r.cidCreateLock.Unlock()

	for mnPodKey, mnLabels := range mnPods {
		cidKey := key.GetCIDKeyFromLabels(mnLabels, labels.LabelSourceK8s)
		cidName, isNewCID, err := r.allocateCID(cidKey)
		if err != nil {
			failedAllocations++
			r.logger.Error("Failed to allocate CID", "failedAllocations", failedAllocations, logfields.Error, err)
			continue
		}

		mnPodMap[mnPodKey] = true
		r.desiredCIDState.Upsert(cidName, cidKey)
		prevCIDName, _ := r.cidUsageInPods.AssignCIDToPod(mnPodKey, cidName)

		if cidName != prevCIDName {
			r.logger.Info("Cilium Identity allocated for a multi-network pod",
				"podKey", mnPodKey,
				logfields.CIDName, cidName,
				logfields.K8sPodName, fmt.Sprintf("%s/%s", pod.Namespace, pod.Name),
				logfields.OldIdentity, prevCIDName,
				logfields.CIDCreated, isNewCID,
				logfields.Labels, mnLabels)
		}
		// CID deletion is handled by identitygc

		if isNewCID {
			r.queueOps.enqueueReconciliation(CIDItem{cidResourceKey(cidName)}, 0)
		}
	}

	podKey := podResourceKey(pod.Name, pod.Namespace).String()
	r.multiNICPods.Add(podKey, mnPodMap)
	if failedAllocations > 0 {
		return fmt.Errorf("identity allocation failed for %d/%d endpoints for multi-network pod %s", failedAllocations, len(mnPods), podKey)
	}

	return nil
}

// getRelevantLabelsForMultiNICPod returns a mapping between multi network pod
// names and their labels. In this context, one pod can have many multi network
// pod names, each with different labels, because labels depend on the network.
func (r *reconciler) getRelevantLabelsForMultiNICPod(pod *slim_corev1.Pod) (map[string]mnLabels, error) {
	ns, err := r.getNamespace(pod.Namespace)
	if err != nil {
		return nil, err
	}

	_, podLabels, annotations, err := k8s.GetPodMetadata(ns, pod)
	if err != nil {
		return nil, err
	}

	_, interfaceAnnotation, err := labels.FetchMultiNICAnnotation(annotations)
	if err != nil {
		return nil, err
	}

	podKey := podResourceKey(pod.Name, pod.Namespace).String()
	mnPods := make(map[string]mnLabels)

	if len(interfaceAnnotation) == 0 {
		addMNPod(mnPods, podKey, networkv1.DefaultPodNetworkName, podLabels)
		return mnPods, nil
	}

	for _, in := range interfaceAnnotation {
		if in.Network == nil {
			continue
		}
		addMNPod(mnPods, podKey, *in.Network, podLabels)
	}

	return mnPods, nil
}

func addMNPod(mnPods map[string]mnLabels, podKey, network string, podLabels map[string]string) {
	mnPodKey := fmt.Sprintf("%s-%s", podKey, network)

	// Deep copy the labels, and add the multinetwork label.
	lbls := make(mnLabels)
	for k, v := range podLabels {
		lbls[k] = v
	}

	mnLabel := labels.GetMultiNICNetworkLabel(network)
	mnLabelSplit := strings.Split(mnLabel, "=")
	mnLabelKey := mnLabelSplit[0]
	mnLabelVal := mnLabelSplit[1]
	lbls[mnLabelKey] = mnLabelVal

	mnPods[mnPodKey] = lbls
}
