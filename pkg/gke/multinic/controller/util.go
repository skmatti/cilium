package controller

import (
	"context"
	"fmt"
	"net"
	"sort"

	networkv1 "github.com/GoogleCloudPlatform/gke-networking-api/apis/network/v1"
	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	anutils "gke-internal.googlesource.com/anthos-networking/apis/v2/utils"
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
func getNetworkStatusMap(node *slim_corev1.Node) (map[string]networkv1.NodeNetworkStatus, error) {
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
func getNorthInterfaces(node *slim_corev1.Node) (map[string]string, error) {
	result := make(map[string]string)
	niAnnotationString, ok := node.GetAnnotations()[networkv1.NorthInterfacesAnnotationKey]
	if !ok {
		// north-interface will be missing if there is no non-default network
		return result, nil
	}
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

// ensureVlanID ensures that an interface named `parentIntName.vlanID` exists with
// the proper vlan ID
func ensureVlanID(vlanIntName string, vlanID int, parentLink netlink.Link, log *logrus.Entry) error {
	// check if tagged interface already exists
	link, err := safenetlink.LinkByName(vlanIntName)
	if err == nil {
		origVlan, ok := link.(*netlink.Vlan)
		if !ok {
			return fmt.Errorf("interface %s is not a vlan (%+v)", vlanIntName, origVlan)
		}

		if origVlan.VlanId != vlanID {
			return fmt.Errorf("existing interface %s has vlan id %d, expected %d", vlanIntName, origVlan.VlanId, vlanID)
		}
		if parentLink.Attrs().Index != origVlan.Attrs().ParentIndex {
			return fmt.Errorf("existing interface %s has parent interface %s, expected %s", vlanIntName, origVlan.Attrs().Name, parentLink.Attrs().Name)
		}
	} else {
		vlan := netlink.Vlan{
			LinkAttrs: netlink.LinkAttrs{
				ParentIndex: parentLink.Attrs().Index,
				Name:        vlanIntName,
			},
			VlanId: vlanID,
		}

		if err := netlink.LinkAdd(&vlan); err != nil {
			return fmt.Errorf("failed to create tagged interface %s : %q", vlanIntName, err)
		}

		link = &vlan
	}

	if err := netlink.LinkSetUp(link); err != nil {
		return fmt.Errorf("failed to bring up network vlan interface %q: %v", vlanIntName, err)
	}

	log.WithField("vlan", vlanIntName).Info("Ensured vlan interface")
	return nil
}

func mapNodeToNetwork(ctx context.Context, k8sNode *slim_corev1.Node) []string {
	log := logger.WithField("name", k8sNode.Name)
	// The default pod-network is always expected to be present. Hence, we reconcile on the default pod-network
	// whenever multi-network annotation changes. Note that the default pod-network is not a part of multi-network
	// annotation. The reconciliation flow parses through the multi-network annotation and builds the allocators
	// accordingly.
	nws := []string{
		// TODO(b/269187538): Remove request from the list once DefaultNetworkName is deprecated.
		networkv1.DefaultNetworkName,
		networkv1.DefaultPodNetworkName,
	}

	// Add networks from north-interface annotation, if present
	// we add all since we do not know what was changed.
	items, err := getNorthInterfaces(k8sNode)
	if err != nil {
		// getNorthInterfaces() only returns error if it can't be parsed.
		log.WithError(err).Info("failed to get north interfaces")
		return nws
	}
	log.Infof("mapNodeToNetwork with north interfaces: %+v", items)
	for name := range items {
		nws = append(nws, name)
	}
	return nws
}

func updateNodeNetworkStatusAnnotation(ctx context.Context, node *slim_corev1.Node, networkName string, ipv4, ipv6 string, log *logrus.Entry, isAdd bool) error {
	netStatusMap, err := getNetworkStatusMap(node)
	if err != nil {
		return fmt.Errorf("failed to get network status map from node %q: %v", node.Name, err)
	}

	oldNetAnnotation, exist := netStatusMap[networkName]
	if isAdd {
		if exist && oldNetAnnotation.IPv4Subnet == ipv4 && oldNetAnnotation.IPv6Subnet == ipv6 {
			return nil
		}
		netStatusMap[networkName] = networkv1.NodeNetworkStatus{Name: networkName, IPv4Subnet: ipv4, IPv6Subnet: ipv6}
	} else {
		if !exist {
			return nil
		}
		delete(netStatusMap, networkName)
	}
	netAnnotations, err := marshalNodeNetworkAnnotation(netStatusMap)
	if err != nil {
		return fmt.Errorf("failed to marshal node network annotation %v: %v", netStatusMap, err)
	}

	if node.Annotations == nil {
		node.Annotations = make(map[string]string)
	}
	node.Annotations[networkv1.NodeNetworkAnnotationKey] = netAnnotations
	return nil
}

func addToNodeNetworkStatus(ctx context.Context, node *slim_corev1.Node, networkName string, ipv4, ipv6 string, log *logrus.Entry) error {
	return updateNodeNetworkStatusAnnotation(ctx, node, networkName, ipv4, ipv6, log, true)
}

func deleteFromNetworkStatus(ctx context.Context, node *slim_corev1.Node, networkName string, ipv4, ipv6 string, log *logrus.Entry) error {
	return updateNodeNetworkStatusAnnotation(ctx, node, networkName, ipv4, ipv6, log, false)
}

// deleteVlanID deletes the specified vlan tag in the the Network CR if
// lifecycle is AnthosManaged
// TODO(b/283301614):
func deleteVlanID(network *networkv1.Network, node *slim_corev1.Node, log *logrus.Entry) error {
	if !hasVlanTag(network) {
		return nil
	}

	taggedIntName, _, err := anutils.InterfaceInfo(network, node.GetAnnotations())
	if err != nil {
		log.Errorf("deleteVlanID: Errored generating interface name for network %s: %s", network.Name, err)
		return nil
	}

	link, err := safenetlink.LinkByName(taggedIntName)
	if err != nil {
		if _, ok := err.(netlink.LinkNotFoundError); ok {
			log.Infof("Link for host interface %s for network %s does not exist or was already deleted: %s", taggedIntName, network.Name, err)
			return nil
		}
		return fmt.Errorf("errored getting link for host interface %s for network %s: %w", taggedIntName, network.Name, err)
	}

	log.Infof("Deleting interface %s for network %s", taggedIntName, network.Name)
	err = netlink.LinkDel(link)
	if err != nil {
		return fmt.Errorf("failed to delete vlan %s for network %s: %w", taggedIntName, network.Name, err)
	}

	return nil
}

func hasVlanTag(network *networkv1.Network) bool {
	if network.Spec.L2NetworkConfig == nil || network.Spec.L2NetworkConfig.VlanID == nil {
		return false
	}

	if network.Spec.NetworkLifecycle != nil && *network.Spec.NetworkLifecycle == networkv1.UserManagedLifecycle {
		return false
	}
	return true

}

func ensureInterface(network *networkv1.Network, intfName string, log *logrus.Entry) error {
	scopedLog := log.WithField(logfields.Interface, intfName)
	parentIntName := intfName
	if network.Spec.L2NetworkConfig != nil && network.Spec.L2NetworkConfig.VlanID != nil {
		parentIntName = *network.Spec.NodeInterfaceMatcher.InterfaceName
	}
	link, err := safenetlink.LinkByName(parentIntName)
	if err != nil {
		return fmt.Errorf("failed to find parent interface %s: %q", parentIntName, err)
	}
	if err := netlink.LinkSetUp(link); err != nil {
		return fmt.Errorf("failed to bring up network parent interface %q: %v", parentIntName, err)
	}
	scopedLog.WithField("parentInterface", parentIntName).Info("Ensured parent interface")

	if hasVlanTag(network) {
		if err := ensureVlanID(intfName, int(*network.Spec.L2NetworkConfig.VlanID), link, scopedLog); err != nil {
			return err
		}
	}

	return nil
}

func nodeAnnotationsUpdated(old, new *slim_corev1.Node) bool {
	if old.Annotations[networkv1.NorthInterfacesAnnotationKey] != new.Annotations[networkv1.NorthInterfacesAnnotationKey] {
		return true
	}
	if old.Annotations[networkv1.MultiNetworkAnnotationKey] != new.Annotations[networkv1.MultiNetworkAnnotationKey] {
		return true
	}
	return false
}
