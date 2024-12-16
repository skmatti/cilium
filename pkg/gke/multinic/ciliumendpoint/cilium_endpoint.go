package ciliumendpoint

import (
	"fmt"

	"github.com/cilium/cilium/pkg/endpoint"
	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/types"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/sirupsen/logrus"
)

const (
	// cepAnnotationKey is the annotation key for multi NIC cilium endpoint.
	cepAnnotationKey = "networking.gke.io/multinic"
	enabledMultiNIC  = "true"
)

// AddAnnotationIfMultiNIC adds the multi NIC annotation to the given CiliumEndpoint object
// if the endpoint is a multi NIC endpoint.
func AddAnnotationIfMultiNIC(e *endpoint.Endpoint, cep *cilium_v2.CiliumEndpoint) {
	scopedLog := e.Logger("multinic-cep").WithFields(logrus.Fields{
		logfields.EndpointID: e.ID,
		logfields.DeviceType: e.GetDeviceType(),
		"ciliumEndpointName": fmt.Sprintf("%s/%s", cep.Namespace, cep.Name),
	})
	if !e.IsMultiNIC() {
		return
	}
	scopedLog.Info("Adding annotation to multi NIC cep")
	if cep.ObjectMeta.Annotations == nil {
		cep.ObjectMeta.Annotations = map[string]string{}
	}
	cep.ObjectMeta.Annotations[cepAnnotationKey] = enabledMultiNIC
}

// IsMultiNICCEP checks whether the given CiliumEndpoint object
// has the multi NIC annotation.
func IsMultiNICCEP(obj interface{}) bool {
	switch cep := obj.(type) {
	case *cilium_v2.CiliumEndpoint:
		return cep.GetObjectMeta().GetAnnotations()[cepAnnotationKey] == enabledMultiNIC
	case *types.CiliumEndpoint:
		return cep.GetObjectMeta().GetAnnotations()[cepAnnotationKey] == enabledMultiNIC
	}
	return false
}

// GetPodNameFromCEP returns the pod name from the provided CiliumEndpoint.
// 1. For non-multiNIC CEP, return the name of the CiliumEndpoint.
// 2. For multiNIC CEP, extract pod name from the OwnerReferences object. Returns error if not found.
func GetPodNameFromCEP(cep *types.CiliumEndpoint) (string, error) {
	if !IsMultiNICCEP(cep) {
		return cep.Name, nil
	}
	for _, owner := range cep.ObjectMeta.OwnerReferences {
		if owner.Kind == "Pod" {
			return owner.Name, nil
		}
	}
	return "", fmt.Errorf("pod name not found in OwnerReferences for multiNIC CEP %q", cep.Name)
}
