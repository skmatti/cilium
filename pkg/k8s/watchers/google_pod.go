package watchers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/cilium/cilium/pkg/annotation"
	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/datapath/linux/bandwidth"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/gke/multinic/multinicconfig"
	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/sirupsen/logrus"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

func (k *K8sPodWatcher) multinicEndpointsLabelUpdate(podNSName string, oldPodLabels, newPodLabels map[string]string) error {
	if multinicconfig.Enabled() {
		return nil
	}

	podEPs := k.endpointManager.GetEndpointsByPodName(podNSName)
	if len(podEPs) == 0 {
		log.WithField("pod", podNSName).Debug("Endpoints not found for the given pod")
		return nil
	}
	var errs []error
	for _, podEP := range podEPs {
		if !podEP.IsMultiNIC() {
			continue
		}

		err := podEP.UpdateLabelsFrom(oldPodLabels, newPodLabels, labels.LabelSourceK8s)

		if err != nil {
			errs = append(errs, err)
		}

		updateMultiNICCiliumEndpointLabels(k.clientset, podEP, newPodLabels)
	}
	if len(errs) > 0 {
		return fmt.Errorf("updating endpoint labels: %w", errors.Join(errs...))
	}
	return nil
}

func (k *K8sPodWatcher) multinicEndpointsAnnotationUpdate(podNSName string, annoChangedProxy, annoChangedBandwidth, annoChangedNoTrack bool) error {
	if multinicconfig.Enabled() {
		return nil
	}

	podEPs := k.endpointManager.GetEndpointsByPodName(podNSName)
	if len(podEPs) == 0 {
		log.WithField("pod", podNSName).Debugf("Endpoints not found for the given pod")
		return nil
	}
	for _, podEP := range podEPs {
		if !podEP.IsMultiNIC() {
			continue
		}
		if annoChangedProxy {
			podEP.UpdateVisibilityPolicy(func(ns, podName string) (proxyVisibility string, err error) {
				p, err := k.GetCachedPod(ns, podName)
				if err != nil {
					return "", err
				}
				value, _ := annotation.Get(p, annotation.ProxyVisibility, annotation.ProxyVisibilityAlias)
				return value, nil
			})
		}
		if annoChangedBandwidth {
			podEP.UpdateBandwidthPolicy(k.bandwidthManager, func(ns, podName string) (bandwidthEgress string, err error) {
				p, err := k.GetCachedPod(ns, podName)
				if err != nil {
					return "", err
				}
				return p.ObjectMeta.Annotations[bandwidth.EgressBandwidth], nil
			})
		}
		if annoChangedNoTrack {
			podEP.UpdateNoTrackRules(func(ns, podName string) (noTrackPort string, err error) {
				p, err := k.GetCachedPod(ns, podName)
				if err != nil {
					return "", err
				}
				value, _ := annotation.Get(p, annotation.NoTrack, annotation.NoTrackAlias)
				return value, nil
			})
		}
		realizePodAnnotationUpdate(podEP)
	}
	return nil
}

// updateMultiNICCiliumEndpointLabels runs a controller associated with the endpoint that updates
// the Labels in CiliumEndpoint object by mirroring those of the associated Pod.
func updateMultiNICCiliumEndpointLabels(clientset client.Clientset, ep *endpoint.Endpoint, labels map[string]string) {
	var (
		controllerName = fmt.Sprintf("sync-pod-labels-with-cilium-endpoint (%v)", ep.GetID())
		scopedLog      = log.WithField("controller", controllerName)
	)

	// The controller is executed only once and is associated with the underlying endpoint object.
	// This is to make sure that the controller is also deleted once the endpoint is gone.
	ep.UpdateController(controllerName,
		controller.ControllerParams{
			DoFunc: func(ctx context.Context) (err error) {
				cepName := ep.GetK8sCEPName()
				scopedLog = scopedLog.WithField(logfields.CEPName, cepName)

				pod := ep.GetPod()
				if pod == nil {
					err := errors.New("Skipping CiliumEndpoint update because it has no k8s pod")
					scopedLog.WithFields(logrus.Fields{
						logfields.EndpointID: ep.GetID(),
						logfields.Labels:     logfields.Repr(labels),
					}).Info(err)
					return err
				}
				ciliumClient := clientset.CiliumV2()

				replaceLabels := []k8s.JSONPatch{
					{
						OP:    "replace",
						Path:  "/metadata/labels",
						Value: labels,
					},
				}

				labelsPatch, err := json.Marshal(replaceLabels)
				if err != nil {
					scopedLog.WithError(err).Debug("Error marshalling Pod labels")
					return err
				}

				_, err = ciliumClient.CiliumEndpoints(pod.GetNamespace()).Patch(
					ctx, cepName,
					types.JSONPatchType,
					labelsPatch,
					meta_v1.PatchOptions{})
				if err != nil {
					scopedLog.WithError(err).Debug("Error while updating CiliumEndpoint object with new Pod labels")
					return err
				}

				scopedLog.WithFields(logrus.Fields{
					logfields.EndpointID: ep.GetID(),
					logfields.Labels:     logfields.Repr(labels),
				}).Info("Updated CiliumEndpoint object with new Pod labels")

				return nil
			},
		})
}
