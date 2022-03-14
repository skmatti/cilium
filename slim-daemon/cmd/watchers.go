package cmd

import (
	"github.com/cilium/cilium/pkg/comparator"
	idcache "github.com/cilium/cilium/pkg/identity/cache"
	"github.com/cilium/cilium/pkg/k8s/informer"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	k8sUtils "github.com/cilium/cilium/pkg/k8s/utils"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/labelsfilter"
	"github.com/cilium/cilium/pkg/logging/logfields"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/slim-daemon/k8s"
	"github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
)

type k8sWatcher struct {
	endpointManager   *EndpointManager
	identityAllocator *idcache.CachingIdentityAllocator
}

func NewK8sWatcher() *k8sWatcher {
	// This needs to be done after the node addressing has been configured
	// as the node address is required as suffix.
	// well known identities have already been initialized above.
	// Ignore the channel returned by this function, as we want the global
	// identity allocator to run asynchronously.
	identityAllocator := idcache.NewCachingIdentityAllocator(dummyIdentityAllocatorOwner{})
	identityAllocator.InitIdentityAllocator(k8s.CiliumClient(), nil)

	return &k8sWatcher{
		endpointManager:   NewEndpointManager(),
		identityAllocator: identityAllocator,
	}
}

func (k *k8sWatcher) initPodWatcher(k8sClient kubernetes.Interface) {
	// Only watch for pod events for our node.
	_, podController := k.createPodController(
		k8sClient.CoreV1().RESTClient(),
		fields.ParseSelectorOrDie("spec.nodeName="+nodeTypes.GetName()))
	ch := make(chan struct{})
	go podController.Run(ch)
}

func (k *k8sWatcher) createPodController(getter cache.Getter, fieldSelector fields.Selector) (cache.Store, cache.Controller) {
	return informer.NewInformer(
		cache.NewListWatchFromClient(getter,
			"pods", v1.NamespaceAll, fieldSelector),
		&slim_corev1.Pod{},
		0,
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				if pod := k8s.ObjTov1Pod(obj); pod != nil {
					podNSName := k8sUtils.GetObjNamespaceName(&pod.ObjectMeta)
					err := k.addK8sPodV1(pod)
					if err != nil {
						log.WithError(err).WithField("pod", podNSName).Error("Failed to add k8s.pod")
					}
				}
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				if oldPod := k8s.ObjTov1Pod(oldObj); oldPod != nil {
					if newPod := k8s.ObjTov1Pod(newObj); newPod != nil {
						if !oldPod.DeepEqual(newPod) {
							err := k.updateK8sPodV1(oldPod, newPod)
							if err != nil {
								log.WithError(err).Error("Failed to update k8s.pod")
							}
						}
					}
				}
			},
			DeleteFunc: func(obj interface{}) {
				if pod := k8s.ObjTov1Pod(obj); pod != nil {
					err := k.deleteK8sPodV1(pod)
					if err != nil {
						log.WithError(err).WithField("pod", pod.Name).Error("Failed to delete k8s.pod")
					}
				}
			},
		},
		nil,
	)
}

func (k *k8sWatcher) addK8sPodV1(pod *slim_corev1.Pod) error {
	scopedLog := log.WithField("pod", pod.Namespace+"/"+pod.Name)
	scopedLog.Info("create pod")

	if len(pod.Status.PodIPs) == 0 {
		scopedLog.Info("skipping addK8sPodV1 because empty status.podIPs")
		return nil
	}

	if pod.Spec.HostNetwork {
		scopedLog.Info("skipping addK8sPodV1 because hostNetwork")
		return nil
	}

	if _, err := k.endpointManager.Lookup(pod.Namespace, pod.Name); err != nil {
		if IsNotFound(err) { /* isNotFound */
			endpoint, err2 := NewEndpoint(pod, k.identityAllocator)
			if err2 != nil {
				return err2
			}
			k.endpointManager.Expose(endpoint)
			return nil
		} else {
			return err
		}
	}

	return errAlreadyExist
}

func (k *k8sWatcher) updateK8sPodV1(oldK8sPod, newK8sPod *slim_corev1.Pod) error {
	var (
		endpoint *Endpoint
		err      error
		needInit bool
	)

	scopedLog := log.WithField("pod", newK8sPod.Namespace+"/"+newK8sPod.Name)
	scopedLog.Info("update pod")

	if len(newK8sPod.Status.PodIPs) == 0 {
		scopedLog.Info("skipping updateK8sPodV1 because empty status.podIPs")
		return nil
	}

	if newK8sPod.Spec.HostNetwork {
		scopedLog.Info("skipping addK8sPodV1 because hostNetwork")
		return nil
	}

	if endpoint, err = k.endpointManager.Lookup(newK8sPod.Namespace, newK8sPod.Name); err != nil {
		if IsNotFound(err) { /* isNotFound */
			needInit = true
		} else {
			return err
		}
	}

	oldPodLabels := oldK8sPod.ObjectMeta.Labels
	newPodLabels := newK8sPod.ObjectMeta.Labels

	if needInit {
		endpoint, err = NewEndpoint(newK8sPod, k.identityAllocator)
		if err != nil {
			return err
		}
		k.endpointManager.Expose(endpoint)
	} else if !comparator.MapStringEquals(oldPodLabels, newPodLabels) {
		// Label has chanaged
		err := updateEndpointLabels(endpoint, oldPodLabels, newPodLabels)
		if err != nil {
			return err
		}
	}

	return nil
}

func (k *k8sWatcher) deleteK8sPodV1(pod *slim_corev1.Pod) error {
	var (
		endpoint *Endpoint
		err      error
	)

	scopedLog := log.WithField("pod", pod.Namespace+"/"+pod.Name)
	scopedLog.Info("delete pod")

	if endpoint, err = k.endpointManager.Lookup(pod.Namespace, pod.Name); err != nil {
		return err
	}

	k.endpointManager.Unexpose(endpoint)

	return nil
}

func updateEndpointLabels(ep *Endpoint, oldLbls, newLbls map[string]string) error {
	oldLabels := labels.Map2Labels(oldLbls, labels.LabelSourceK8s)
	newLabels := labels.Map2Labels(newLbls, labels.LabelSourceK8s)
	log.WithField("labels", oldLbls).Info("old labels")
	log.WithField("labels", newLabels).Info("new labels")
	newIdtyLabels, _ := labelsfilter.Filter(newLabels)
	oldIdtyLabels, _ := labelsfilter.Filter(oldLabels)

	err := ep.ModifyIdentityLabels(newIdtyLabels, oldIdtyLabels)
	if err != nil {
		log.WithError(err).Debugf("Error while updating endpoint with new labels")
		return err
	}

	log.WithFields(logrus.Fields{
		logfields.EndpointID: ep.GetID(),
		logfields.Labels:     logfields.Repr(newIdtyLabels),
	}).Debug("Updated endpoint with new labels")
	return nil
}
