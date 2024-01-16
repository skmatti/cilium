package ciliumidentity

import (
	"fmt"
	"strings"

	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	networkv1 "k8s.io/cloud-provider-gcp/crd/apis/network/v1"

	"github.com/cilium/cilium/operator/watchers"
	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/lock"
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

func (m *multiNICPods) GetMNPodMap(podFullName string) mnPodCache {
	m.mu.RLock()
	defer m.mu.RUnlock()

	mnPodMap := m.mnPods[podFullName]
	return mnPodMap
}

func (m *multiNICPods) Add(podFullName string, mnPodMap mnPodCache) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.mnPods[podFullName] = mnPodMap
}

func (m *multiNICPods) Remove(podFullName string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.mnPods, podFullName)
}

// reconcileMultiNICPod treats every network interface as a separate pod.
func (r *reconciler) reconcileMultiNICPod(podKey resource.Key) error {
	if !r.googleMultiNICEnabled {
		return fmt.Errorf("google multi network is not enabled, but pod reconciliation for multi-network pod is called")
	}

	podFullName := podKey.String()

	podObj, exists, err := watchers.PodStore.GetByKey(podFullName)
	if err != nil && !k8serrors.IsNotFound(err) {
		return err
	}
	// When a pod is not found in the pod store, it means it's deleted.
	if !exists {
		mnPodMap := r.multiNICPods.GetMNPodMap(podFullName)
		for mnPodName := range mnPodMap {
			prevCIDName, count, found := r.cidUsageInPods.RemovePod(mnPodName)
			if found && count == 0 && !r.cidIsUsedInCEPOrCES(prevCIDName) {
				r.cleanUpCID(prevCIDName)
			}
		}

		r.multiNICPods.Remove(podFullName)
		return nil
	}

	pod, ok := podObj.(*slim_corev1.Pod)
	if !ok {
		return fmt.Errorf("wrong type (%T) of object when getting Pod %q from the Pod watcher store", podObj, podKey.String())
	}

	mnPods, err := r.getRelevantLabelsForMultiNICPod(pod)
	if err != nil {
		return err
	}

	mnPodMap := make(mnPodCache)
	for mnPodName, mnLabels := range mnPods {
		mnPodMap[mnPodName] = true

		cidName, err := r.allocateCID(mnLabels)
		if err != nil {
			log.Error(err)
			continue
		}

		prevCIDName, count := r.cidUsageInPods.AssignCIDToPod(mnPodName, cidName)
		if len(prevCIDName) > 0 && count == 0 && !r.cidIsUsedInCEPOrCES(prevCIDName) {
			r.cleanUpCID(prevCIDName)
		}
	}

	r.multiNICPods.Add(podFullName, mnPodMap)

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

	podFullName := podResourceKey(pod.Name, pod.Namespace).String()
	mnPods := make(map[string]mnLabels)

	if len(interfaceAnnotation) == 0 {
		addMNPod(mnPods, podFullName, networkv1.DefaultPodNetworkName, podLabels)
		return mnPods, nil
	}

	for _, in := range interfaceAnnotation {
		if in.Network == nil {
			continue
		}
		addMNPod(mnPods, podFullName, *in.Network, podLabels)
	}

	return mnPods, nil
}

func addMNPod(mnPods map[string]mnLabels, podFullName, network string, podLabels map[string]string) {
	mnPodName := fmt.Sprintf("%s-%s", podFullName, network)

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

	mnPods[mnPodName] = lbls
}
