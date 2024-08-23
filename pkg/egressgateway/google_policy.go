package egressgateway

import (
	networkv1 "k8s.io/cloud-provider-gcp/crd/apis/network/v1"

	k8slbls "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/labels"
)

// defaultVPCNetwork is the Default-VPC network in GDCH Lancer Architecture.
const defaultVPCNetwork = "default-vpc"

// skipEgressNATPolicy returns true if egress NAT policies
// must be disabled for the endpoint associated with
// given labels.
// Currently, all multinic endpoints that are not in default-vpc
// network are skipped.
func skipEgressNATPolicy(lblsToMatch k8slbls.Labels) bool {
	network := lblsToMatch.Get(networkv1.NetworkAnnotationKey)
	return network != "" && !networkv1.IsDefaultNetwork(network) && network != defaultVPCNetwork
}
