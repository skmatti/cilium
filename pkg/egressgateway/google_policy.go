package egressgateway

import (
	networkv1 "github.com/GoogleCloudPlatform/gke-networking-api/apis/network/v1"
	k8sLbls "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/labels"

	"github.com/cilium/cilium/pkg/gke/features"
)

// skipEgressNATPolicy returns true if egress NAT policies
// must be disabled for the endpoint associated with
// given labels.
// Returns false if enable-google-multi-nic-egress-nat is set to true.
// Otherwise, returns false only for non multi nic endpoints.
func skipEgressNATPolicy(lblsToMatch k8sLbls.Labels) bool {
	if features.GlobalConfig.EnableGoogleMultiNICEgressNAT {
		return false
	}
	network := lblsToMatch.Get(networkv1.NetworkAnnotationKey)
	return network != "" && !networkv1.IsDefaultNetwork(network)
}
