package egressgateway

import (
	k8sLbls "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/labels"
	networkv1 "k8s.io/cloud-provider-gcp/crd/apis/network/v1"
)

// isMultiNICEndpoint returns true if the endpoint has multi-network label
// and not in the pod-network.
func isMultiNICEndpoint(lblsToMatch k8sLbls.Labels) bool {
	network := lblsToMatch.Get(networkv1.NetworkAnnotationKey)
	return network != "" && network != networkv1.DefaultNetworkName
}
