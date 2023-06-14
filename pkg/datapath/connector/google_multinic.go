// Copyright 2021 Authors of Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package connector

import (
	"errors"
	"fmt"
	"hash/crc32"
	"math/rand"
	"net"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/defaults"
	dhcp "github.com/cilium/cilium/pkg/gke/multinic/dhcp"
	multinicep "github.com/cilium/cilium/pkg/gke/multinic/endpoint"
	"github.com/cilium/cilium/pkg/gke/multinic/nic"
	"github.com/cilium/cilium/pkg/ipam"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/netns"
	"github.com/cilium/cilium/pkg/node"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	anutils "gke-internal.googlesource.com/anthos-networking/apis/v2/utils"
	"golang.org/x/sys/unix"
	"k8s.io/apimachinery/pkg/types"
	networkv1 "k8s.io/cloud-provider-gcp/crd/apis/network/v1"
	"k8s.io/utils/pointer"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	kubevirtMacvtapResourcePrefix = "macvtap.network.kubevirt.io"

	metricAllocate = "allocate"
	metricRelease  = "release"
	familyIPv4     = "ipv4"
	familyIPv6     = "ipv6"
)

// interfaceConfiguration holds network properties needed to configure the interface.
type interfaceConfiguration struct {
	// IPV4Address is in CIDR annotation and holds single IPV4 address applied to the macvlan/macvtap interface.
	// e.g. 1.2.3.4/24
	IPV4Address         *net.IPNet
	MacAddress          net.HardwareAddr
	ParentInterfaceName string
	MTU                 int
	Type                string
	// When true, IFF_ALLMULTI is enabled for the interface.
	EnableMulticast bool
	// Network id in the google multinic context, configured for L3 multinic devices only
	NetworkID uint32
}

func isIPV6(ip net.IP) bool {
	return ip.To4() == nil
}

// parseIPSubnet parses ip address string from NetworkInterface CR to IPNet with IP and Mask.
// The provided string may be in CIDR annotation.
// If not, /32 is taken for IPV4 and /128 is taken for IPV6 by default.
func parseIPSubnet(addr string) (*net.IPNet, error) {
	ip, ipNet, err := net.ParseCIDR(addr)
	if err == nil {
		if isIPV6(ip) {
			return nil, fmt.Errorf("IPV6 is not supported for macvlan/macvtap interface")
		}
		return &net.IPNet{
			IP:   ip,
			Mask: ipNet.Mask,
		}, nil
	}
	// Check if the IP address string is in IP format without subnet length
	ip = net.ParseIP(addr)
	if ip == nil {
		return nil, fmt.Errorf("failed to parse IP %q", addr)
	}
	var mask net.IPMask
	if isIPV6(ip) {
		return nil, fmt.Errorf("IPV6 is not supported for macvlan/macvtap interface")
	}
	mask = net.CIDRMask(32, 32)
	return &net.IPNet{
		IP:   ip,
		Mask: mask,
	}, nil
}

func parseIPRoutes(routes []networkv1.Route) ([]*net.IPNet, error) {
	var res []*net.IPNet
	for _, rt := range routes {
		ip, ipNet, err := net.ParseCIDR(rt.To)
		if err != nil {
			return nil, fmt.Errorf("failed to parse CIDR: %v", err)
		}
		if ones, _ := ipNet.Mask.Size(); ones == 0 {
			return nil, fmt.Errorf("CIDR length must be over 0: %s", rt.To)
		}
		if isIPV6(ip) {
			return nil, fmt.Errorf("ipv6 route %q is not supported", rt.To)
		}
		res = append(res, ipNet)
	}
	return res, nil
}

// getInterfaceConfiguration returns interfaceConfiguration which is needed to configure the macvlan/macvtap interface.
// The function also enforces some necessary checks of the configuration and returns a proper error message.
func getInterfaceConfiguration(intf *networkv1.NetworkInterface, network *networkv1.Network, podResources map[string][]string) (*interfaceConfiguration, error) {
	intfID := types.NamespacedName{
		Name:      intf.Name,
		Namespace: intf.Namespace,
	}
	if len(intf.Spec.IpAddresses) > 1 {
		return nil, fmt.Errorf("found %d IP addresses in the interface CR %q. Only single IPv4 address is supported for L2 interface", len(intf.Spec.IpAddresses), intfID.String())
	}

	var (
		cfg    interfaceConfiguration
		macStr string
		err    error
	)
	if len(intf.Spec.IpAddresses) != 0 {
		cfg.IPV4Address, err = parseIPSubnet(intf.Spec.IpAddresses[0])
		if err != nil {
			return nil, fmt.Errorf("failed to get a valid IP in the interface CR %q: %v", intfID.String(), err)
		}
	}

	if intf.Spec.MacAddress != nil {
		macStr = *intf.Spec.MacAddress
	} else if intf.Status.MacAddress != "" {
		macStr = intf.Status.MacAddress
	}
	if macStr != "" {
		cfg.MacAddress, err = net.ParseMAC(macStr)
		if err != nil {
			return nil, fmt.Errorf("unable to parse MAC in the interface CR %q: %v", intfID.String(), err)
		}
	}

	cfg.ParentInterfaceName, _, err = anutils.InterfaceInfo(network, node.GetAnnotations())
	if err != nil {
		return nil, fmt.Errorf("parent interface name is empty in the network CR %q: %s", network.Name, err)
	}
	if _, isMacvtap := podResources[macvtapResourceName(cfg.ParentInterfaceName)]; isMacvtap {
		cfg.Type = multinicep.EndpointDeviceMACVTAP
	} else if network.Spec.Type == networkv1.L3NetworkType {
		cfg.Type = multinicep.EndpointDeviceMultinicVETH
		cfg.NetworkID = GenerateNetworkID(network)
	} else {
		cfg.Type = multinicep.EndpointDeviceMACVLAN
	}

	return &cfg, nil
}

func GenerateNetworkID(network *networkv1.Network) uint32 {
	return crc32.ChecksumIEEE([]byte(network.UID))
}

func applyIPToLink(ipAddr *net.IPNet, l netlink.Link) error {
	log.WithFields(logrus.Fields{
		logfields.IPAddr: ipAddr,
	}).Debug("Configuring link ip address")

	addr := &netlink.Addr{IPNet: ipAddr}

	if isIPV6(ipAddr.IP) {
		addr.Flags = unix.IFA_F_NODAD
	}
	if err := netlink.AddrAdd(l, addr); err != nil {
		return fmt.Errorf("failed to add addr %v to %q: %v", addr.String(), l.Attrs().Name, err)
	}
	return nil
}

func applyMACToLink(macAddr net.HardwareAddr, l netlink.Link) error {
	log.WithFields(logrus.Fields{
		logfields.MACAddr: macAddr.String(),
	}).Debug("Configuring link mac address")

	if err := netlink.LinkSetHardwareAddr(l, macAddr); err != nil {
		return fmt.Errorf("failed to add MAC addr %q to %q: %v", macAddr.String(), l.Attrs().Name, err)
	}
	return nil
}

func addRoutes(dstRanges []*net.IPNet, gwAddr *net.IP, l netlink.Link, routeMTU int) error {
	for _, r := range dstRanges {
		rt := &netlink.Route{
			LinkIndex: l.Attrs().Index,
			Scope:     netlink.SCOPE_UNIVERSE,
			Dst:       r,
			MTU:       routeMTU,
		}
		if gwAddr == nil {
			rt.Scope = netlink.SCOPE_LINK
		} else {
			rt.Gw = *gwAddr
		}
		log.WithField("route", logfields.Repr(rt)).Debug("Adding route")
		if err := netlink.RouteAdd(rt); err != nil {
			return fmt.Errorf("failed to add route '%s via dev %s': %v",
				r.String(), l.Attrs().Name, err)
		}
	}
	return nil
}

func addDefaultRoute(gwAddr *net.IP, l netlink.Link) error {
	if gwAddr == nil {
		return errors.New("default route must have a valid gateway address")
	}
	log.WithFields(logrus.Fields{
		logfields.InterfaceInPod: l.Attrs().Name,
		"gw":                     gwAddr.String(),
	}).Debug("Add default route")
	dr := &netlink.Route{
		LinkIndex: l.Attrs().Index,
		Scope:     netlink.SCOPE_UNIVERSE,
		Gw:        *gwAddr,
		Dst:       nil,
	}
	if err := netlink.RouteReplace(dr); err != nil {
		return fmt.Errorf("failed to add a default route via dev %s with gw %s: %v",
			l.Attrs().Name, gwAddr.String(), err)
	}
	return nil
}

// configureInterface applies IP configuration to the target interface with the provided interface configuration.
func configureInterface(cfg *interfaceConfiguration, netNs ns.NetNS, ifName string) error {
	configure := func(_ ns.NetNS) error {
		l, err := netlink.LinkByName(ifName)
		if err != nil {
			return fmt.Errorf("failed to lookup interface %q: %v", ifName, err)
		}
		if err = netlink.LinkSetMTU(l, cfg.MTU); err != nil {
			return fmt.Errorf("unable to set MTU %d to %q: %v", cfg.MTU, l.Attrs().Name, err)
		}

		if cfg.MacAddress != nil && cfg.Type != "ipvlan" {
			if err := applyMACToLink(cfg.MacAddress, l); err != nil {
				return fmt.Errorf("failed to apply mac address to %q: %v", l.Attrs().Name, err)
			}
		} else {
			if l.Attrs() == nil {
				return errors.New("no link attributes found")
			}
			cfg.MacAddress = l.Attrs().HardwareAddr
		}
		if err := applyIPToLink(cfg.IPV4Address, l); err != nil {
			return fmt.Errorf("failed to apply IP configuration: %v", err)
		}

		if cfg.EnableMulticast {
			if err := netlink.LinkSetAllmulticastOn(l); err != nil {
				return fmt.Errorf("failed to set link %q Allmulticast on: %v", ifName, err)
			}
		}

		if cfg.Type != multinicep.EndpointDeviceMACVTAP {
			if err := netlink.LinkSetUp(l); err != nil {
				return fmt.Errorf("failed to set link %q UP: %v", ifName, err)
			}
		} else {
			// b/280340190: keep the macvtap interface down so that it doesn't
			// affect vm live migration.
			log.Info("Skip turning on macvtap interface")
		}
		return nil
	}
	if err := netNs.Do(configure); err != nil {
		return fmt.Errorf("unable to configure interface %q in container namespace: %s", ifName, err)
	}

	return nil
}

// macvtapResourceName returns the macvtap resource name with the prefix.
func macvtapResourceName(name string) string {
	return kubevirtMacvtapResourcePrefix + "/" + name
}

// RevertMacvtapSetup performs operations to revert macvtap setup done in SetupMacvtapChild(), including
// removing bpf filter and clsact qdisc, renaming and moving link back to the global namespace.
func RevertMacvtapSetup(ifNameInPod, ifName, nsPath string) error {
	netNs, err := ns.GetNS(nsPath)
	if err != nil {
		return fmt.Errorf("failed to open netns %q: %v", nsPath, err)
	}
	defer netNs.Close()

	// Assume the caller is running in host global netns
	globalNetNS, err := ns.GetCurrentNS()
	if err != nil {
		return fmt.Errorf("failed to open host global netns: %v", err)
	}
	defer globalNetNS.Close()

	if err := netNs.Do(func(_ ns.NetNS) error {
		l, err := netlink.LinkByName(ifNameInPod)
		if err != nil {
			return fmt.Errorf("failed to lookup interface %q: %v", ifNameInPod, err)
		}

		if err := netlink.LinkSetDown(l); err != nil {
			return fmt.Errorf("failed to set link %q DOWN: %v", ifNameInPod, err)
		}

		if err := removeBpfFilter(l, IngressMapIndex); err != nil {
			return fmt.Errorf("failed to remove ingress bpf filter: %v", err)
		}
		if err := removeBpfFilter(l, EgressMapIndex); err != nil {
			return fmt.Errorf("failed to remove egress bpf filter: %v", err)
		}

		qdisc := clsactQdisc(l.Attrs().Index)
		if err = netlink.QdiscDel(qdisc); err != nil {
			return fmt.Errorf("failed to remove clsact qdisc on %q: %s", ifNameInPod, err)
		}

		if ifNameInPod != ifName {
			if err = netlink.LinkSetName(l, ifName); err != nil {
				return fmt.Errorf("failed to rename interface from %q to %q: %s", ifNameInPod, ifName, err)
			}
		}

		// Move the macvtap link back to the global namespace on the host.
		if err = netlink.LinkSetNsFd(l, int(globalNetNS.Fd())); err != nil {
			return fmt.Errorf("failed to move macvtap link %q back to global netns %q: %v", l.Attrs().Name, globalNetNS.Path(), err)
		}

		return nil
	}); err != nil {
		return fmt.Errorf("failed to revert macvtap setup in container namespace %q: %v", nsPath, err)
	}

	return nil
}

func RevertDeviceInterface(ifNameInPod string, network *networkv1.Network, nsPath string, paramsRef client.Object) error {
	gkeparam, ok := paramsRef.(*networkv1.GKENetworkParamSet)
	if !ok {
		return fmt.Errorf("failed to cast to networkv1.GKENetworkparams, type is %T value: %v", paramsRef, paramsRef)
	}
	if gkeparam.Spec.DeviceMode == networkv1.DPDKVFIO {
		//DPDK device will end up in root netns upon driver bind
		log.Debugf("skipping reversion for DPDK network %s, ", network.Name)
		return nil
	}
	netNs, err := ns.GetNS(nsPath)
	if err != nil {
		return fmt.Errorf("failed to open netns %q: %v", nsPath, err)
	}
	defer netNs.Close()

	// Assume the caller is running in host global netns
	// This works because we lock the OS thread, which means
	// we (or any other netNs.Do) can't be preempted
	globalNetNS, err := ns.GetCurrentNS()
	if err != nil {
		return fmt.Errorf("failed to open host global netns: %v", err)
	}
	defer globalNetNS.Close()
	birthName, _, _, err := getNameIPAndPCIAddressFromNetwork(network, log)
	var tempName string
	if err != nil {
		return fmt.Errorf("failed to get interface pci address from network %v, err: %v", network, err)
	}
	if err := netNs.Do(func(_ ns.NetNS) error {
		// We use name here on the assumption that the interface has to be with the right name
		iface, err := netlink.LinkByName(ifNameInPod)
		if err != nil {
			return fmt.Errorf("failed to get link %s, err: %v", ifNameInPod, err)
		}

		if err := netlink.LinkSetDown(iface); err != nil {
			return fmt.Errorf("failed to set link %q DOWN: %v", iface.Attrs().Name, err)
		}
		tempName = "gketmp" + fmt.Sprint(rand.Intn(1000000))
		log.Infof("Setting Device name to tempname %s in reverting Device network", tempName)
		if err = netlink.LinkSetName(iface, tempName); err != nil {
			return fmt.Errorf("failed to rename interface from %q to %q: %v", iface.Attrs().Name, tempName, err)
		}

		// Move the interface back to the global namespace on the host.
		if err = netlink.LinkSetNsFd(iface, int(globalNetNS.Fd())); err != nil {
			return fmt.Errorf("failed to move Device link %q back to global netns %q: %v", iface.Attrs().Name, globalNetNS.Path(), err)
		}
		return nil
	}); err != nil {
		return fmt.Errorf("failed to revert Device setup in container namespace %q: %v", nsPath, err)
	}
	iface, err := netlink.LinkByName(tempName)
	if err != nil {
		return fmt.Errorf("failed to lookup interface %q: %v", tempName, err)
	}
	// we ignore error here because altname only matters for Ubuntu, but we call unconditionally
	output, err := nic.RemoveAltnameFromInterface(iface.Attrs().Name, birthName)
	if err != nil {
		log.Infof("tried to remove altname %s from interface %s, got error %v, output %s", birthName, tempName, err, output)
	}

	if err = netlink.LinkSetName(iface, birthName); err != nil {
		// systemd will race us with putting it back up, so we set it back down for rename
		if err := netlink.LinkSetDown(iface); err != nil {
			return fmt.Errorf("failed to set interface %s down %v", tempName, err)
		}
		if err = netlink.LinkSetName(iface, birthName); err != nil {
			return fmt.Errorf("failed to rename interface from %q to %q: %s", tempName, birthName, err)
		}
	}
	if err := netlink.LinkSetUp(iface); err != nil {
		return fmt.Errorf("failed to set interface %s up", birthName)
	}
	log.Infof("Reverted device %s for Device network %s", birthName, network.Name)

	return nil
}
func createMacvlanChild(ifName string, parentDevIndex int) error {
	var err error

	if parentDevIndex == 0 {
		return errors.New("invalid parent device ifindex")
	}

	macvlan := &netlink.Macvlan{
		LinkAttrs: netlink.LinkAttrs{
			Name:        ifName,
			ParentIndex: parentDevIndex,
		},
		Mode: netlink.MACVLAN_MODE_BRIDGE,
	}

	if err = netlink.LinkAdd(macvlan); err != nil {
		return fmt.Errorf("unable to create macvlan child device: %v", err)
	}

	log.WithFields(logrus.Fields{
		logfields.Macvlan: ifName,
		"parentIndex":     parentDevIndex,
	}).Debug("Created macvlan child interface")

	return nil
}

func createIPvlanChild(ifName string, parentDevIndex int) error {
	var err error

	if parentDevIndex == 0 {
		return errors.New("invalid parent device ifindex")
	}

	ipvlan := &netlink.IPVlan{
		LinkAttrs: netlink.LinkAttrs{
			Name:        ifName,
			ParentIndex: parentDevIndex,
		},
		Mode: netlink.IPVLAN_MODE_L2,
	}

	if err = netlink.LinkAdd(ipvlan); err != nil {
		return fmt.Errorf("unable to create ipvlan child device: %v", err)
	}

	log.WithFields(logrus.Fields{
		logfields.Ipvlan: ifName,
		"parentIndex":    parentDevIndex,
	}).Debug("Created ipvlan child interface")

	return nil
}

// SetupL2Interface sets up the l2 interface (macvlan/macvtap). If the pre-allocated pod resource exists,
// the function sets up a macvtap interface. Otherwise, it creates a new macvlan interface attached to
// the provided parent interface and sets it up.
// The set up operations consist moving the interface to the remote network namespace, initializing
// bpf tail call map on both directions (see setupInterfaceInRemoteNs), and configuring the interface.
func SetupL2Interface(ifNameInPod, podName string, podResources map[string][]string, network *networkv1.Network, intf *networkv1.NetworkInterface, ep *models.EndpointChangeRequest, dc dhcp.DHCPClient, ipam *ipam.IPAM) (func(), error) {
	cfg, err := getInterfaceConfiguration(intf, network, podResources)
	if err != nil {
		return nil, fmt.Errorf("failed to get a valid interface configuration: %v", err)
	}
	cfg.EnableMulticast = ep.DatapathConfiguration.EnableMulticast
	log.Debugf("L2 interface configuration: %+v", cfg)
	parentDevLink, err := netlink.LinkByName(cfg.ParentInterfaceName)
	if err != nil {
		return nil, fmt.Errorf("failed to lookup parent interface %q: %v", cfg.ParentInterfaceName, err)
	}
	// TODO(yfshen): get MTU information from interface CR.
	cfg.MTU = parentDevLink.Attrs().MTU

	var srcIfName string
	var cleanup func()
	ep.DeviceType = cfg.Type
	switch cfg.Type {
	case multinicep.EndpointDeviceMACVLAN:
		srcIfName = Endpoint2TempRandIfName()
		err := createMacvlanChild(srcIfName, parentDevLink.Attrs().Index)
		if err != nil {
			return nil, err
		}
		cleanup = func() {
			if err = DeleteInterfaceInRemoteNs(ifNameInPod, ep.NetworkNamespace); err != nil {
				log.WithError(err).WithField(logfields.Macvlan, srcIfName).Warn("failed to clean up macvlan")
			}
			releaseIP(network, cfg, ipam)
		}
	case multinicep.EndpointDeviceIPVLAN:
		srcIfName = Endpoint2TempRandIfName()
		err := createIPvlanChild(srcIfName, parentDevLink.Attrs().Index)
		if err != nil {
			return nil, err
		}
		cleanup = func() {
			if err = DeleteInterfaceInRemoteNs(ifNameInPod, ep.NetworkNamespace); err != nil {
				log.WithError(err).WithField(logfields.Ipvlan, srcIfName).Warn("failed to clean up ipvlan")
			}
			releaseIP(network, cfg, ipam)
		}
	case multinicep.EndpointDeviceMACVTAP:
		macvtapIfNames := podResources[macvtapResourceName(cfg.ParentInterfaceName)]
		if len(macvtapIfNames) != 1 {
			return nil, fmt.Errorf("found %d macvtap interface for parent interface %q: only single macvtap interface is supported", len(macvtapIfNames), cfg.ParentInterfaceName)
		}
		srcIfName = macvtapIfNames[0]
		cleanup = func() {
			if err = RevertMacvtapSetup(ifNameInPod, srcIfName, ep.NetworkNamespace); err != nil {
				log.WithError(err).WithField(logfields.Macvtap, srcIfName).Warn("failed to revert macvtap")
			}
			releaseIP(network, cfg, ipam)
		}
	default:
		return nil, fmt.Errorf("unknown interface type: %v", cfg.Type)
	}

	log.WithFields(logrus.Fields{
		logfields.DeviceType:     ep.DeviceType,
		logfields.InterfaceInPod: ifNameInPod,
		logfields.NetNSName:      ep.NetworkNamespace,
		"sourceInterface":        srcIfName,
		"parentInterface":        cfg.ParentInterfaceName,
	}).Info("Set up L2 interface")

	link, err := netlink.LinkByName(srcIfName)
	if err != nil {
		return cleanup, fmt.Errorf("failed to lookup interface %q: %v", srcIfName, err)
	}

	if err = DisableRpFilter(srcIfName); err != nil {
		return cleanup, err
	}

	netNs, err := ns.GetNS(ep.NetworkNamespace)
	if err != nil {
		return cleanup, fmt.Errorf("failed to open netns %q: %v", ep.NetworkNamespace, err)
	}
	defer netNs.Close()

	// Move the link to the target network namespace.
	if err = netlink.LinkSetNsFd(link, int(netNs.Fd())); err != nil {
		return cleanup, fmt.Errorf("failed to move link %q to netns %q: %v", link.Attrs().Name, netNs.Path(), err)
	}

	m, err := setupInterfaceInRemoteNs(netNs, srcIfName, ifNameInPod, true)
	if err != nil {
		return cleanup, fmt.Errorf("unable to setup link %q in remote netns: %v", link.Attrs().Name, err)
	}
	defer m.Close()

	info, err := m.Info()
	if err != nil {
		return cleanup, fmt.Errorf("failed to get map info: %w", err)
	}

	mapID, exists := info.ID()
	if !exists {
		return cleanup, errors.New("failed to get map ID")
	}

	dhcpResp, err := configureDHCPInfo(network, cfg, dc, ep.NetworkNamespace, ifNameInPod, ep.ContainerID)
	if err != nil {
		return cleanup, fmt.Errorf("failed to query DHCP information: %v", err)
	}

	if err := configureIPAMInfo(network, cfg, ifNameInPod, ipam); err != nil {
		return cleanup, fmt.Errorf("failed to query IPAM information: %v", err)
	}

	if err := configureInterface(cfg, netNs, ifNameInPod); err != nil {
		return cleanup, fmt.Errorf("failed to configure interface: %v", err)
	}

	if err := populateInterfaceStatus(intf, network, cfg, dhcpResp, podName, nil); err != nil {
		return cleanup, fmt.Errorf("failed to populate interface status: %v", err)
	}

	// Update the endpoint addressing after the macvlan interface is configured.
	ep.Addressing.IPV4 = cfg.IPV4Address.IP.String()
	ep.Mac = cfg.MacAddress.String()
	ep.HostMac = parentDevLink.Attrs().HardwareAddr.String()
	ep.InterfaceName = srcIfName
	ep.InterfaceIndex = int64(link.Attrs().Index)
	ep.InterfaceNameInPod = ifNameInPod
	ep.ParentDeviceIndex = int64(parentDevLink.Attrs().Index)
	ep.ParentDeviceName = parentDevLink.Attrs().Name
	ep.ParentDeviceMac = parentDevLink.Attrs().HardwareAddr.String()
	ep.DatapathMapID = int64(mapID)
	ep.ExternalDHCP4 = dhcpResp != nil

	return cleanup, nil
}

func SetupL3Interface(ifNameInPod, podName string, podResources map[string][]string, network *networkv1.Network, intf *networkv1.NetworkInterface, ep *models.EndpointChangeRequest, ipam *ipam.IPAM, paramsRef client.Object) (func(), error) {
	cfg, err := getInterfaceConfiguration(intf, network, podResources)
	if err != nil {
		return nil, fmt.Errorf("failed to get a valid interface configuration: %v", err)
	}
	log.Debugf("L3 interface configuration: %+v", cfg)
	parentDevLink, err := netlink.LinkByName(cfg.ParentInterfaceName)
	if err != nil {
		return nil, fmt.Errorf("failed to lookup parent interface %q: %v", cfg.ParentInterfaceName, err)
	}
	// TODO(yfshen): get MTU information from interface CR.
	cfg.MTU = parentDevLink.Attrs().MTU

	var peerIfName string
	var peer netlink.Link
	var veth *netlink.Veth
	var cleanup func()
	ep.DeviceType = cfg.Type
	switch cfg.Type {
	case multinicep.EndpointDeviceMultinicVETH:
		// We cannot use ep.ContainerID here as it's already used by the default interface.
		// Hence we use "ep.ContainerID-network" to differetiate & ensure consistency.
		// Here we use peerIfName as handle to setup link in remote ns. However the ep.InterfaceName
		// should be veth.Name used for loading bpf_lxc during datapath reload, rather than peerIfName
		// for other L2 device types.
		veth, peer, peerIfName, err = SetupVeth(ep.ContainerID+network.Name, int(cfg.MTU), ep)
		if err != nil {
			return nil, fmt.Errorf("unable to set up veth on host side: %s", err)
		}
		cleanup = func() {
			if err != nil {
				if err2 := netlink.LinkDel(veth); err2 != nil {
					log.WithError(err2).WithField(logfields.Veth, veth.Name).Warn("failed to clean up and delete veth")
				}
			}
		}
	default:
		return nil, fmt.Errorf("unknown interface type: %v", cfg.Type)
	}

	log.WithFields(logrus.Fields{
		logfields.DeviceType:     ep.DeviceType,
		logfields.InterfaceInPod: ifNameInPod,
		logfields.NetNSName:      ep.NetworkNamespace,
		"sourceInterface":        peerIfName,
		"parentInterface":        cfg.ParentInterfaceName,
	}).Info("Set up L3 interface")

	netNs, err := ns.GetNS(ep.NetworkNamespace)
	if err != nil {
		return cleanup, fmt.Errorf("failed to open netns %q: %v", ep.NetworkNamespace, err)
	}
	defer netNs.Close()

	// Move the link to the target network namespace.
	if err = netlink.LinkSetNsFd(peer, int(netNs.Fd())); err != nil {
		return cleanup, fmt.Errorf("failed to move link %q to netns %q: %v", peer.Attrs().Name, netNs.Path(), err)
	}

	_, _, err = SetupVethRemoteNs(netNs, peerIfName, ifNameInPod)
	if err != nil {
		return cleanup, fmt.Errorf("unable to setup veth %q in remote netns: %v", peer.Attrs().Name, err)
	}

	if err := configureIPAMInfo(network, cfg, ifNameInPod, ipam); err != nil {
		return cleanup, fmt.Errorf("failed to query IPAM information: %v", err)
	}

	if err := configureInterface(cfg, netNs, ifNameInPod); err != nil {
		return cleanup, fmt.Errorf("failed to configure interface: %v", err)
	}

	if err := populateInterfaceStatus(intf, network, cfg, nil, podName, paramsRef); err != nil {
		return cleanup, fmt.Errorf("failed to populate interface status: %v", err)
	}

	// Update the endpoint addressing after the veth interface is configured.
	ep.Addressing.IPV4 = cfg.IPV4Address.IP.String()
	ep.ParentDeviceMac = parentDevLink.Attrs().HardwareAddr.String()
	ep.InterfaceName = veth.Name
	ep.InterfaceNameInPod = ifNameInPod
	ep.ParentDeviceIndex = int64(parentDevLink.Attrs().Index)
	ep.ParentDeviceName = parentDevLink.Attrs().Name
	ep.DatapathConfiguration.NetworkID = cfg.NetworkID

	return cleanup, nil
}

// this section is a repeat of code in the controller, but an import would be a circular dependency
type nicMapValue struct {
	pciAddress string
	birthName  string
}

// map from ip to pciaddress, birth name
// Uses node.GetAnnotations(), does *not* make any api calls
func getNicInfo() (map[string]nicMapValue, error) {
	nicAnnotationString, ok := node.GetAnnotations()[networkv1.NICInfoAnnotationKey]
	if !ok {
		return nil, fmt.Errorf("nic-info annotation does not exist, looking for annotation with key %s", networkv1.NICInfoAnnotationKey)
	}
	result := make(map[string]nicMapValue)
	if nicAnnotationString == "" {
		return nil, fmt.Errorf("nic-info annotation is empty")
	}
	nicAnnotation, err := networkv1.ParseNICInfoAnnotation(nicAnnotationString)
	if err != nil {
		return nil, fmt.Errorf("error parsing nic-info annotation: %v", err)
	}
	for _, n := range nicAnnotation {
		result[n.BirthIP] = nicMapValue{n.PCIAddress, n.BirthName}
	}

	return result, nil
}

// map from network to ip
// Uses code.GetAnnotations(), does *not* make any api calls
func getNorthInterfaces(log *logrus.Entry) (map[string]string, error) {
	niAnnotationString, ok := node.GetAnnotations()[networkv1.NorthInterfacesAnnotationKey]
	if !ok {
		return nil, fmt.Errorf("north interfaces annotation does not exist, looking for annotation with key %s, node annotations: %v", networkv1.NorthInterfacesAnnotationKey, node.GetAnnotations())
	}
	result := make(map[string]string)
	if niAnnotationString == "" {
		log.Debugf("North interfaces annotation empty:")
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

func getNameIPAndPCIAddressFromNetwork(network *networkv1.Network, log *logrus.Entry) (string, net.IP, string, error) {
	networkName := network.Name
	ni, err := getNorthInterfaces(log)

	addr, exists := ni[networkName]
	if !exists {
		return "", nil, "", fmt.Errorf("couldn't find network %s in north interface annotation: %v", networkName, ni)
	}

	nicInfo, err := getNicInfo()
	if err != nil {
		return "", nil, "", err
	}
	info, exists := nicInfo[addr]
	if !exists {
		return "", nil, "", fmt.Errorf("Could not find nic with ip %v in annotation", addr)
	}
	netIP := net.ParseIP(addr)
	return info.birthName, netIP, info.pciAddress, nil
}

func ifaceFromPCIAddress(addr string) (netlink.Link, error) {
	links, err := netlink.LinkList()
	if err != nil {
		return nil, fmt.Errorf("failed to list links: %v", err)
	}
	for i := range links {
		ifaceName := links[i].Attrs().Name
		pciAddr, err := nic.ToPCIAddr(ifaceName)
		if err != nil {
			// we just ignore devices we can't get the address of
			continue
		}
		if pciAddr == addr {
			return links[i], nil
		}
	}
	return nil, fmt.Errorf("could not find a device with address %s", addr)
}

// SetupDeviceInterface moves a Device into a pod and renames it. Does no setup on DPDK networks. Returns a cleanup function and a bool to indicate DPDK or not
func SetupDeviceInterface(ifNameInPod, podName string, podResources map[string][]string, network *networkv1.Network, intf *networkv1.NetworkInterface, ep *models.EndpointChangeRequest, paramsRef client.Object) (func(), bool, error) {
	// All the steps we do are replay-able because we use PCI address
	// pretty sure we could remove this from our function signature
	var cleanup func()
	// we skip route creation on dpdk device creation
	isDPDK := true
	localLog := log.WithFields(logrus.Fields{
		logfields.InterfaceInPod: ifNameInPod,
		logfields.NetNSName:      ep.NetworkNamespace,
	})
	localLog.Info("Setting up Device interface")
	gkeparam, ok := paramsRef.(*networkv1.GKENetworkParamSet)
	if !ok {
		return cleanup, false, fmt.Errorf("failed to cast to networkv1.GKENetworkparams, type is %T value: %v", paramsRef, paramsRef)
	}

	// we use PCI address to handle cases where a CNI_DEL has crashed, and
	// our device is stuck with either a customer provided name or
	// a weird temp name.
	_, ipAddr, ifacePCIAddr, err := getNameIPAndPCIAddressFromNetwork(network, log)
	if err != nil {
		return cleanup, false, fmt.Errorf("failed to get interface pci address from network %v, err: %v", network, err)
	}
	var mac net.HardwareAddr = nil

	ipNet := net.IPNet{IP: ipAddr, Mask: net.CIDRMask(32, 32)}
	ifaceAddr := &netlink.Addr{IPNet: &ipNet}

	// DPDK devices require no additional setup. The device will be unbound by pci address
	if gkeparam.Spec.DeviceMode != networkv1.DPDKVFIO {
		iface, err := ifaceFromPCIAddress(ifacePCIAddr)
		if err != nil {
			return cleanup, false, fmt.Errorf("failed to get link %s, err: %v", ifacePCIAddr, err)
		}
		localLog.Debugf("found device %s for NetDevice network", iface.Attrs().Name)
		mac = iface.Attrs().HardwareAddr

		isDPDK = false
		localLog.Info("Configuring a NetDevice")
		if err := netlink.LinkSetDown(iface); err != nil {
			return cleanup, false, fmt.Errorf("failed to set link %q DOWN: %v", iface.Attrs().Name, err)
		}
		cid := ep.ContainerID
		// use last 8B of container ID for a unique tempname
		tempName := "gketmp"
		if len(cid) > 8 {
			tempName = tempName + cid[len(cid)-8:]
		} else {
			tempName = tempName + cid
		}
		// interface names have a limit of 15 chars
		localLog.Debugf("setting device name to tempname: %s", tempName)
		if err = netlink.LinkSetName(iface, tempName); err != nil {
			return cleanup, false, fmt.Errorf("failed to rename interface from %q to %q: %v", iface.Attrs().Name, tempName, err)
		}

		netNs, err := ns.GetNS(ep.NetworkNamespace)
		if err != nil {
			return cleanup, false, fmt.Errorf("failed to open netns %q: %v", ep.NetworkNamespace, err)
		}
		defer netNs.Close()

		// Move the link to the target network namespace.
		if err = netlink.LinkSetNsFd(iface, int(netNs.Fd())); err != nil {
			return cleanup, false, fmt.Errorf("failed to move link %q to netns %q: %v", iface.Attrs().Name, netNs.Path(), err)
		}
		if err := netNs.Do(func(_ ns.NetNS) error {
			// We get the iface again in the new ns, as the handle is namespaced
			iface, err := netlink.LinkByName(tempName)
			if err != nil {
				return fmt.Errorf("failed to get link %s, err: %v", tempName, err)
			}
			localLog.Debugf("setting device %s, name to final name: %s", tempName, ifNameInPod)
			if err = netlink.LinkSetName(iface, ifNameInPod); err != nil {
				return fmt.Errorf("failed to rename interface from %q to %q: %v", tempName, ifNameInPod, err)
			}

			if err = netlink.AddrAdd(iface, ifaceAddr); err != nil {
				return fmt.Errorf("failed to add IP %v to interface %s", ipAddr, ifNameInPod)
			}
			if err := netlink.LinkSetUp(iface); err != nil {
				return fmt.Errorf("failed to set link %q UP: %v", ifNameInPod, err)
			}
			return nil
		}); err != nil {
			return cleanup, false, err
		}

	}
	ifcfg := interfaceConfiguration{
		IPV4Address: &ipNet,
		MacAddress:  mac,
	}
	err = populateInterfaceStatus(intf, network, &ifcfg, nil, podName, paramsRef)
	if err != nil {
		return cleanup, isDPDK, err
	}
	// we pass the IP out for purposes of setting the pod-ips annotation
	ep.Addressing.IPV4 = ipAddr.String()

	return cleanup, isDPDK, nil
}

// DeleteInterfaceInRemoteNs deletes the L2 interface (macvlan/ipvlan) in the remote network namespace.
func DeleteInterfaceInRemoteNs(ifName, nsPath string) error {
	netNs, err := ns.GetNS(nsPath)
	if err != nil {
		return fmt.Errorf("failed to open netns %q: %v", nsPath, err)
	}
	defer netNs.Close()

	if err := netns.RemoveIfFromNetNSIfExists(netNs, ifName); err != nil {
		log.WithError(err).Warningf("Unable to delete interface %s in namespace %q, will not delete interface", ifName, nsPath)
		// We are not returning an error as this is very unlikely to be recoverable
	}
	return nil
}

// SetupNetworkRoutes configures custom routes and default route if defined in the provided interface cr
// status on the interface in the pod namespace.
// Route mtu is only set for the pod network. Otherwise, pass 0 to ignore the configuration.
func SetupNetworkRoutes(ifNameInPod string, intf *networkv1.NetworkInterface, netCR *networkv1.Network, nsPath string,
	isDefaultInterface bool, podNetworkMTU int, skipInstallation bool) error {
	log.WithFields(logrus.Fields{
		logfields.InterfaceInPod: ifNameInPod,
		logfields.NetNSName:      nsPath,
		logfields.MTU:            podNetworkMTU,
		"network":                intf.Spec.NetworkName,
		"isDefaultInterface":     isDefaultInterface,
	}).Info("Set up network routes")

	var (
		destCIDRs []*net.IPNet
		gw        *net.IP
		err       error
		mtu       int
	)

	if networkv1.IsDefaultNetwork(intf.Spec.NetworkName) {
		mtu = podNetworkMTU
	}
	if len(intf.Status.Routes) != 0 {
		destCIDRs, err = parseIPRoutes(intf.Status.Routes)
		if err != nil {
			return fmt.Errorf("failed to parse IP routes for the interface CR %q: %v", intf.Name, err)
		}
	}
	if intf.Status.Gateway4 != nil {
		gwIPv4 := net.ParseIP(*intf.Status.Gateway4)
		if gwIPv4 == nil || isIPV6(gwIPv4) {
			return fmt.Errorf("failed to get a valid IPv4 gateway address: %s", *intf.Status.Gateway4)
		}
		gw = &gwIPv4
	}
	if isDefaultInterface && !networkv1.IsDefaultNetwork(intf.Spec.NetworkName) && gw == nil {
		return fmt.Errorf("gateway must be configued for default interface network: %s", intf.Spec.NetworkName)
	}
	if skipInstallation {
		return nil
	}
	netNs, err := ns.GetNS(nsPath)
	if err != nil {
		return fmt.Errorf("failed to open netns %q: %v", nsPath, err)
	}
	defer netNs.Close()

	if err := netNs.Do(func(_ ns.NetNS) error {
		l, err := netlink.LinkByName(ifNameInPod)
		if err != nil {
			return fmt.Errorf("failed to lookup interface %q: %v", ifNameInPod, err)
		}

		// Link needs to be up before applying routes.
		if err := netlink.LinkSetUp(l); err != nil {
			return fmt.Errorf("failed to set link %q UP: %v", ifNameInPod, err)
		}

		// Add a route to gateway for L3 or Device network excepet the default network
		if netCR != nil && (netCR.Spec.Type == networkv1.L3NetworkType || netCR.Spec.Type == networkv1.DeviceNetworkType) && !networkv1.IsDefaultNetwork(netCR.Name) {
			if gw == nil {
				return errors.New("gateway for L3/Device network should not be nil")
			}
			log.WithFields(logrus.Fields{
				logfields.InterfaceInPod: ifNameInPod,
				logfields.NetNSName:      nsPath,
				logfields.MTU:            podNetworkMTU,
				"network":                intf.Spec.NetworkName,
				"isDefaultInterface":     isDefaultInterface,
				"gateway":                *gw,
			}).Info("Set up route to gateway for L3/Device network")
			if err := addRoutes([]*net.IPNet{{IP: *gw, Mask: defaults.ContainerIPv4Mask}}, nil, l, mtu); err != nil {
				return err
			}
		}
		if err := addRoutes(destCIDRs, gw, l, mtu); err != nil {
			return err
		}
		// No need to re-configure the default route for default pod-network.
		if isDefaultInterface && !networkv1.IsDefaultNetwork(intf.Spec.NetworkName) {
			if err := addDefaultRoute(gw, l); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		return err
	}
	return nil
}

func configureDHCPInfo(network *networkv1.Network, cfg *interfaceConfiguration, dc dhcp.DHCPClient, podNS, podIface, containerID string) (*dhcp.DHCPResponse, error) {
	if network.Spec.ExternalDHCP4 == nil || *network.Spec.ExternalDHCP4 == false {
		// No DHCP is required when externalDHCP4 is false or not set
		return nil, nil
	}

	parentInterface, _, err := anutils.InterfaceInfo(network, node.GetAnnotations())
	if err != nil {
		return nil, fmt.Errorf("failed to configure dhcp info for %s: %s", network.Name, err)
	}

	staticConfig := isStaticNetwork(network)
	if cfg.IPV4Address != nil {
		if !staticConfig {
			return nil, errors.New("static IP requested when static information is not provided in network")
		}
		return nil, nil
	}

	macAddr := cfg.MacAddress.String()
	dhcpInfo, err := dc.GetDHCPResponse(containerID, podNS, podIface, parentInterface, &macAddr)
	if err != nil {
		return nil, err
	}

	if dhcpInfo == nil {
		return nil, nil
	}

	if len(dhcpInfo.IPAddresses) == 0 {
		return nil, errors.New("dhcp response does not have any ip addresses")
	}
	cfg.IPV4Address = dhcpInfo.IPAddresses[0]

	// if Network has static information, only the IPAddress should be returned
	if staticConfig {
		return &dhcp.DHCPResponse{IPAddresses: dhcpInfo.IPAddresses}, nil
	}
	return dhcpInfo, nil
}

func configureIPAMInfo(network *networkv1.Network, cfg *interfaceConfiguration, podIface string, ipam *ipam.IPAM) error {
	// no IPAM required when external DHCP is true.
	if network.Spec.ExternalDHCP4 != nil && *network.Spec.ExternalDHCP4 == true {
		return nil
	}
	if cfg.IPV4Address != nil {
		if !isStaticNetwork(network) {
			return errors.New("static IP requested when static information is not provided in network")
		}
		// TODO - Reserve the static IP in the allocator once kubevirt has the
		// CCC changes and network object changes in place with respect to the provider field.
		return nil
	}
	ipam.MultiNetworkAllocatorMutex.Lock()
	defer ipam.MultiNetworkAllocatorMutex.Unlock()
	ipa := ipam.MultiNetworkAllocators[network.Name]
	if ipa == nil {
		return fmt.Errorf("ipam allocator not found for network %s", network.Name)
	}
	result, err := ipa.AllocateNext(podIface)
	if err != nil {
		return err
	}
	var mask []byte
	if network.Spec.Type == networkv1.L3NetworkType {
		mask = net.CIDRMask(32, 8*net.IPv4len)
	} else {
		// TODO - Remove this check and add logic to read the mask from
		// node interface when PrefixLength4 is not set.
		if network.Spec.L2NetworkConfig == nil || network.Spec.L2NetworkConfig.PrefixLength4 == nil {
			return fmt.Errorf("prefixLengthV4 field not set for L2 network %s", network.Name)
		}
		prefixLen := int(*network.Spec.L2NetworkConfig.PrefixLength4)
		mask = net.CIDRMask(prefixLen, 8*net.IPv4len)
	}
	cfg.IPV4Address = &net.IPNet{
		IP:   result.IP,
		Mask: mask,
	}
	log.Infof("Reserved ip address %s with mask %s", cfg.IPV4Address.IP.String(), cfg.IPV4Address.Mask.String())
	metrics.MultiNetworkIpamEvent.WithLabelValues(metricAllocate, network.Name, familyIPv4).Inc()
	return nil
}

func releaseIP(network *networkv1.Network, cfg *interfaceConfiguration, ipam *ipam.IPAM) {
	if network.Spec.ExternalDHCP4 != nil && *network.Spec.ExternalDHCP4 {
		return
	}
	if cfg.IPV4Address == nil {
		return
	}
	ipam.MultiNetworkAllocatorMutex.Lock()
	defer ipam.MultiNetworkAllocatorMutex.Unlock()
	ipa, ok := ipam.MultiNetworkAllocators[network.Name]
	if !ok {
		return
	}
	if err := ipa.Release(cfg.IPV4Address.IP); err != nil {
		log.WithError(err).Warningf("Unable to release IP %s in network %s", cfg.IPV4Address.IP.String(), network.Name)
	} else {
		log.Infof("Released IP %s that was reserved", cfg.IPV4Address.IP.String())
		metrics.MultiNetworkIpamEvent.WithLabelValues(metricRelease, network.Name, familyIPv4).Inc()
	}
}

func isDNSConfigured(network *networkv1.Network) bool {
	if network.Spec.DNSConfig == nil {
		return false
	}

	config := *network.Spec.DNSConfig
	if len(config.Nameservers) > 0 || len(config.Searches) > 0 {
		return true
	}
	return false
}

func isStaticNetwork(network *networkv1.Network) bool {
	// If Network has any static information, the network is considered static.
	routesConfigured := len(network.Spec.Routes) > 0
	gatewayConfigured := network.Spec.Gateway4 != nil && *(network.Spec.Gateway4) != ""
	dnsConfigured := isDNSConfigured(network)

	return routesConfigured || gatewayConfigured || dnsConfigured
}

func extractRoutes(network *networkv1.Network, netParamsObj client.Object) ([]networkv1.Route, error) {
	ret := network.Spec.Routes
	if netParamsObj == nil {
		return ret, nil
	}
	if network.Spec.Type == networkv1.L3NetworkType || network.Spec.Type == networkv1.DeviceNetworkType {
		if gkeparam, ok := netParamsObj.(*networkv1.GKENetworkParamSet); ok {
			for _, cidr := range gkeparam.Status.PodCIDRs.CIDRBlocks {
				ret = append(ret, networkv1.Route{To: cidr})
			}
		} else {
			return nil, fmt.Errorf("Expected GKENetworkParamSet but got unknown param struct [%T] %+v", netParamsObj, netParamsObj)
		}
	}
	return ret, nil
}

func populateInterfaceStatus(intf *networkv1.NetworkInterface, network *networkv1.Network, cfg *interfaceConfiguration, dhcpResp *dhcp.DHCPResponse, podName string, netParamsObj client.Object) error {
	// Update the interface status after IP and MAC address are configured successfully.
	intf.Status.IpAddresses = []string{cfg.IPV4Address.String()}
	intf.Status.MacAddress = cfg.MacAddress.String()
	intf.Status.PodName = pointer.StringPtr(podName)
	intf.Status.Routes = network.Spec.Routes
	intf.Status.Gateway4 = network.Spec.Gateway4
	intf.Status.DNSConfig = network.Spec.DNSConfig
	// Respect DHCP response if not nil and override interface parameters with DHCP response values.
	if dhcpResp != nil {
		intf.Status.Routes = dhcpResp.Routes
		intf.Status.Gateway4 = dhcpResp.Gateway4
		intf.Status.DNSConfig = dhcpResp.DNSConfig
	}
	if network.Spec.Type == networkv1.L3NetworkType {
		routes, err := extractRoutes(network, netParamsObj)
		if err != nil {
			return err
		}
		intf.Status.Routes = routes
		if intf.Status.Gateway4 == nil {
			// For L3 network, if gateway is not specified in network,
			// use the first IP from the network's pod CIDR on node as gateway IP.
			podNetworks := node.GetPodNetworks()
			cidr, ok := podNetworks[network.Name]
			if !ok {
				return fmt.Errorf("ipam cidr for network %s does not exist", network.Name)
			}
			gwIp := ipam.DeriveGatewayIP(cidr.String())
			intf.Status.Gateway4 = &gwIp
		}
	} else if network.Spec.Type == networkv1.DeviceNetworkType {
		routes, err := extractRoutes(network, netParamsObj)
		if err != nil {
			return err
		}
		intf.Status.Routes = routes
		if intf.Status.Gateway4 == nil {
			gkeparam, ok := netParamsObj.(*networkv1.GKENetworkParamSet)
			if !ok {
				return fmt.Errorf("failed to get GKENetworkparams from %v", gkeparam)
			}
			if gkeparam.Status.PodCIDRs == nil {
				return fmt.Errorf("No PodCIDR for pod %s found in gnp %v", podName, gkeparam)
			}
			ranges := gkeparam.Status.PodCIDRs.CIDRBlocks
			if len(ranges) == 0 {
				return fmt.Errorf("No CIDRBlocks for pod %s found in gnp %v", podName, gkeparam)
			}
			addrString := ranges[0]
			// For Device network, if gateway is not specified in network,
			// use the first IP from the network's pod CIDR on node as gateway IP.
			gwIp := ipam.DeriveGatewayIP(addrString)
			intf.Status.Gateway4 = &gwIp
		}
	}
	return nil
}
