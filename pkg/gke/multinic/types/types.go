package types

import (
	"fmt"
	"net"

	"github.com/cilium/cilium/pkg/cidr"
	"github.com/cilium/cilium/pkg/ip"
	networkv1 "gke-internal.googlesource.com/anthos-networking/apis/v2/network/v1"
)

// MultiNetworkIPAMManager defines methods to handle the multi-network allocators
type MultiNetworkIPAMManager interface {
	// UpdateMultiNetworkIPAMAllocators updates the daemon's multi-network allocators with the new networks.
	UpdateMultiNetworkIPAMAllocators(annotations map[string]string) error
}

// BuildMultiNetworkCIDRs parses the multi-network annotation on a node and builds a name-cidr map per network.
func BuildMultiNetworkCIDRs(multiNwAnnotation string) (map[string]*cidr.CIDR, error) {
	nodeNws, err := networkv1.ParseMultiNetworkAnnotation(multiNwAnnotation)
	if err != nil {
		return nil, fmt.Errorf("invalid format for multi-network annotation: %v", err)
	}
	res := map[string]*cidr.CIDR{}
	for _, n := range nodeNws {
		_, ipNet, err := net.ParseCIDR(n.Cidrs[0])
		if err != nil {
			return nil, fmt.Errorf("invalid network cidr %s", n.Cidrs[0])
		}
		if !ip.IsIPv4(ipNet.IP) {
			return nil, fmt.Errorf("only networks with ipv4 addresses are supported")
		}
		res[n.Name] = cidr.NewCIDR(ipNet)
	}
	return res, nil
}
