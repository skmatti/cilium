package controller

import (
	"fmt"
	"net"
	"sort"

	"github.com/vishvananda/netlink"
	corev1 "k8s.io/api/core/v1"
	networkv1 "k8s.io/cloud-provider-gcp/crd/apis/network/v1"
)

func findInSlice(arr []string, s string) int {
	for i := range arr {
		if arr[i] == s {
			return i
		}
	}
	return -1
}
func findNetworkInSlice(arr []networkv1.Network, s string) int {
	for i := range arr {
		if arr[i].Name == s {
			return i
		}
	}
	return -1
}

// bestAddrMatch scans the given list of IP addresses and returns the one that
// "best" fits the match of what we consider the nodes IP address on the
// network. An IP that has the global attribute, along with the largest subnet
// range is considered the best match. We do this to filter out IPs such as ANG
// floating IPs which have a /32 cidr range and local IP addresses.
//
// e.g 10.0.0.1/28 > 10.0.0.2/30
func bestAddrMatch(addrs []netlink.Addr) *net.IPNet {
	var ipNet *net.IPNet
	for _, addr := range addrs {
		if netlink.Scope(addr.Scope) == netlink.SCOPE_UNIVERSE {
			if ipNet == nil {
				ipNet = addr.IPNet
				continue
			}

			// Check and replace if the cidr is larger to remove addresses added
			// to the interface by ANG and to get the largest subnet supported
			// by that network.
			ipNetPrefixSize, _ := ipNet.Mask.Size()
			addrPrefixSize, _ := addr.IPNet.Mask.Size()
			if ipNetPrefixSize > addrPrefixSize {
				ipNet = addr.IPNet
			}
		}
	}
	return ipNet
}

// getNetworkStatusMap returns a map of networks to the corresponding status on the node.
// The information is parsed from the node annotation.
func getNetworkStatusMap(node *corev1.Node) (map[string]networkv1.NodeNetworkStatus, error) {
	netStatusMap := make(map[string]networkv1.NodeNetworkStatus)
	annotation := node.Annotations[networkv1.NodeNetworkAnnotationKey]
	if len(annotation) == 0 {
		return netStatusMap, nil
	}
	netAnn, err := networkv1.ParseNodeNetworkAnnotation(annotation)
	if err != nil {
		return nil, err
	}
	for _, n := range netAnn {
		netStatusMap[n.Name] = n
	}
	return netStatusMap, nil
}

func marshalNodeNetworkAnnotation(statusMap map[string]networkv1.NodeNetworkStatus) (string, error) {
	ann := make(networkv1.NodeNetworkAnnotation, 0, len(statusMap))
	for _, net := range statusMap {
		ann = append(ann, net)
	}
	sort.Slice(ann, func(i, j int) bool {
		return ann[i].Name < ann[j].Name
	})
	return networkv1.MarshalNodeNetworkAnnotation(ann)
}

// getNorthInterfaces returns a map from network to ip.
func getNorthInterfaces(node *corev1.Node) (map[string]string, error) {
	niAnnotationString, ok := node.GetAnnotations()[networkv1.NorthInterfacesAnnotationKey]
	if !ok {
		return nil, fmt.Errorf("north interfaces annotation does not exist, looking for annotation with key %s, node annotations: %v", networkv1.NorthInterfacesAnnotationKey, node.GetAnnotations())
	}
	result := make(map[string]string)
	if niAnnotationString == "" {
		return result, nil
	}
	niAnnotation, err := networkv1.ParseNorthInterfacesAnnotation(niAnnotationString)
	if err != nil {
		return nil, fmt.Errorf("error parsing north interfaces annotation: %v", err)
	}
	for _, n := range niAnnotation {
		result[n.Network] = n.IpAddress
	}

	return result, nil
}

func copySlice(src []string) []string {
	dst := make([]string, len(src))
	copy(dst, src)
	return dst
}
