package utils

import (
	"fmt"
	"net"
	"strings"

	networkv1 "k8s.io/cloud-provider-gcp/crd/apis/network/v1"
)

// InterfaceInfo returns the name, IP address of the interface on the node that is connected to the network
// passed in the input. It also takes the node annotations as input to look for IP address and determine the interface name
// to handle cases where nodeInterfaceMatcher is not set in the network object. Users of this utility can pass
// nil in the annotations if they prefer to set node interface matcher in the network object and fetch the interface information.
func InterfaceInfo(n *networkv1.Network, annotations map[string]string) (string, string, error) {
	var infName string
	var infIP string
	if n == nil {
		return "", "", fmt.Errorf("network object cannot be nil")
	}
	// find interface name from the network object, if set.
	if n.Spec.NodeInterfaceMatcher.InterfaceName != nil && *n.Spec.NodeInterfaceMatcher.InterfaceName != "" {
		hostInterface := n.Spec.NodeInterfaceMatcher.InterfaceName
		if n.Spec.L2NetworkConfig == nil || n.Spec.L2NetworkConfig.VlanID == nil {
			infName = *hostInterface
		} else {
			infName = fmt.Sprintf("%s.%d", *hostInterface, *n.Spec.L2NetworkConfig.VlanID)
		}
	} else { // extract IP address from north-interface annotation if inf name could not be determined above.
		if annotations == nil {
			return "", "", fmt.Errorf("no node annotations passed, cannot look for any north-interface annotation")
		}
		niAnnotationString, ok := annotations[networkv1.NorthInterfacesAnnotationKey]
		if !ok {
			return "", "", fmt.Errorf("north interfaces annotation does not exist")
		}
		niAnnotation, err := networkv1.ParseNorthInterfacesAnnotation(niAnnotationString)
		if err != nil {
			return "", "", fmt.Errorf("error parsing north interfaces annotation: %v", err)
		}
		for _, ni := range niAnnotation {
			if ni.Network == n.Name {
				infIP = ni.IpAddress
				break
			}
		}
		if infIP == "" {
			return "", "", fmt.Errorf("network %s not found in north interfaces annotation", n.Name)
		}
	}
	interfaces, err := net.Interfaces()
	if err != nil {
		return "", "", fmt.Errorf("error fetching list of system's network interfaces: %v", err)
	}
	for _, inf := range interfaces {
		addrs, err := inf.Addrs()
		if err != nil {
			return "", "", fmt.Errorf("error fetching list of unicast interface addresses for interface %s: %v", inf.Name, err)
		}
		// inf IP addr is known, inf name unknown.
		if infName == "" {
			for _, addr := range addrs {
				ipAddress := strings.Split(addr.String(), "/")[0]
				if ipAddress == infIP {
					return inf.Name, infIP, nil
				}
			}
		} else if infIP == "" { // inf name is known, inf IP addr unknown.
			// TODO(b/268116856) - Define logic to find interface IP address when name is known.
			return infName, "", nil
		}
	}
	return "", "", fmt.Errorf("matching interface does not exist on the node for network %s", n.Name)
}
