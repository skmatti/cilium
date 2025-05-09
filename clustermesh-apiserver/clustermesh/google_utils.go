package clustermesh

import (
	networkv1 "github.com/GoogleCloudPlatform/gke-networking-api/apis/network/v1"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/types"
)

const multinicAnnotation = "networking.gke.io/multinic"
const networkSecurityLabel = "k8s:networking.gke.io/network"

func shouldSyncIdentity(identity *ciliumv2.CiliumIdentity) bool {
	if !syncMultiNicEPs {
		return false
	}
	if identity == nil {
		return false
	}

	if network, ok := identity.SecurityLabels[networkSecurityLabel]; ok {
		if !networkv1.IsDefaultNetwork(network) {
			log.Debugf("Found multinic identity for endpoint %s", identity.Name)
			return true
		}
	}
	return false
}

func shouldSyncCEP(ep *types.CiliumEndpoint) bool {
	if !syncMultiNicEPs {
		return false
	}
	if ep == nil {
		return false
	}

	if _, ok := ep.Annotations[multinicAnnotation]; ok {
		log.Debugf("Found multinic label for endpoint %s", ep.Name)
		return true
	}
	return false
}
