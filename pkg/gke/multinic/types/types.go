package types

import (
	"fmt"
	"net"
	"strings"

	"github.com/cilium/cilium/pkg/cidr"
	"github.com/cilium/cilium/pkg/ip"
	"github.com/cilium/cilium/pkg/node"
	networkv1 "k8s.io/cloud-provider-gcp/crd/apis/network/v1"
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

// InterfaceName returns the expected host interface for this Network
// If vlanID is specified, the expected tagged interface Name is returned
// otherwise the user specified interfaceName is returned
func InterfaceName(n *networkv1.Network) (string, error) {
	if n.Spec.NodeInterfaceMatcher.InterfaceName != nil && *n.Spec.NodeInterfaceMatcher.InterfaceName != "" {
		hostInterface := n.Spec.NodeInterfaceMatcher.InterfaceName

		if n.Spec.L2NetworkConfig == nil || n.Spec.L2NetworkConfig.VlanID == nil {
			return *hostInterface, nil
		}

		return fmt.Sprintf("%s.%d", *hostInterface, *n.Spec.L2NetworkConfig.VlanID), nil
	}

	// For GKE we use L3NetworkType to determine InterfaceName
	if n.Spec.Type == networkv1.L3NetworkType {
		niAnnotationString, ok := node.GetAnnotations()[networkv1.NorthInterfacesAnnotationKey]
		if !ok {
			return "", fmt.Errorf("north interfaces annotation does not exist")
		}
		niAnnotation, err := networkv1.ParseNorthInterfacesAnnotation(niAnnotationString)
		if err != nil {
			return "", fmt.Errorf("error parsing north interfaces annotation: %v", err)
		}
		interfaces, err := net.Interfaces()
		if err != nil {
			return "", fmt.Errorf("error fetching list of system's network interfaces: %v", err)
		}
		for _, ni := range niAnnotation {
			if ni.Network == n.Name {
				for _, inf := range interfaces {
					addrs, err := inf.Addrs()
					if err != nil {
						return "", fmt.Errorf("error fetching list of unicast interface addresses for interface %s: %v", inf.Name, err)
					}
					for _, addr := range addrs {
						ipAddress := strings.Split(addr.String(), "/")[0]
						if ipAddress == ni.IpAddress {
							return inf.Name, nil
						}
					}
					return "", fmt.Errorf("matching interface does not exist for network %s with IP %s", ni.Network, ni.IpAddress)
				}
			}
		}
		return "", fmt.Errorf("network %s not found in north interfaces annotation", n.Name)
	}

	return "", fmt.Errorf("invalid network %s: network.spec.nodeInterfaceMatcher.InterfaceName cannot be nil or empty", n.Name)
}
