package egressgateway

import (
	networkv1 "github.com/GoogleCloudPlatform/gke-networking-api/apis/network/v1"
	k8sLbls "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/labels"
)

// isMultiNICEndpoint returns true if the endpoint has multi-network label
// and not the default pod-network.
func isMultiNICEndpoint(lblsToMatch k8sLbls.Labels) bool {
	network := lblsToMatch.Get(networkv1.NetworkAnnotationKey)
	return network != "" && !networkv1.IsDefaultNetwork(network)
}
