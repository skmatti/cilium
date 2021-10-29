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
	"net"

	"github.com/cilium/cilium/api/v1/models"
	dhcp "github.com/cilium/cilium/pkg/gke/multinic/dhcp"
	multinicep "github.com/cilium/cilium/pkg/gke/multinic/endpoint"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/netns"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	networkv1alpha1 "gke-internal.googlesource.com/anthos-networking/apis/network/v1alpha1"
	"golang.org/x/sys/unix"
	"k8s.io/apimachinery/pkg/types"
)

const (
	kubevirtMacvtapResourcePrefix = "macvtap.network.kubevirt.io"
)

// interfaceConfiguration holds network properties needed to configure the interface.
type interfaceConfiguration struct {
	// IPV4Address is in CIDR annotation and holds single IPV4 address applied to the macvlan/macvtap interface.
	// e.g. 1.2.3.4/24
	IPV4Address         *net.IPNet
	MacAddress          net.HardwareAddr
	ParentInterfaceName string
	MTU                 int
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

func parseIPRoutes(routes []networkv1alpha1.Route) ([]*net.IPNet, error) {
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
func getInterfaceConfiguration(intf *networkv1alpha1.NetworkInterface, network *networkv1alpha1.Network) (*interfaceConfiguration, error) {
	intfID := types.NamespacedName{
		Name:      intf.Name,
		Namespace: intf.Namespace,
	}
	if len(intf.Spec.IpAddresses) > 1 {
		return nil, fmt.Errorf("found %d IP addresses in the interface CR %q. Only single IPv4 address is supported for macvlan/macvtap interface.", len(intf.Spec.IpAddresses), intfID.String())
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

	cfg.ParentInterfaceName, err = network.InterfaceName()
	if err != nil {
		return nil, fmt.Errorf("parent interface name is empty in the network CR %q: %s", network.Name, err)
	}

	return &cfg, nil
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
		log.WithField("route", logfields.Repr(r)).Debug("Adding route")
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
			return fmt.Errorf("unable to set MTU to %q: %v", l.Attrs().Name, err)
		}

		if cfg.MacAddress != nil {
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

		if err := netlink.LinkSetUp(l); err != nil {
			return fmt.Errorf("failed to set link %q UP: %v", ifName, err)
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

func createMacvlanChild(ifName string, parentDevIndex int) (*netlink.Macvlan, error) {
	var err error

	if parentDevIndex == 0 {
		return nil, errors.New("invalid parent device ifindex")
	}

	macvlan := &netlink.Macvlan{
		LinkAttrs: netlink.LinkAttrs{
			Name:        ifName,
			ParentIndex: parentDevIndex,
		},
		Mode: netlink.MACVLAN_MODE_BRIDGE,
	}

	if err = netlink.LinkAdd(macvlan); err != nil {
		return nil, fmt.Errorf("unable to create macvlan child device: %v", err)
	}

	log.WithFields(logrus.Fields{
		logfields.Macvlan: ifName,
		"parentIndex":     parentDevIndex,
	}).Debug("Created macvlan child interface")

	return macvlan, nil
}

// SetupL2Interface sets up the l2 interface (macvlan/macvtap). If the pre-allocated pod resource exists,
// the function sets up a macvtap interface. Otherwise, it creates a new macvlan interface attached to
// the provided parent interface and sets it up.
// The set up operations consist moving the interface to the remote network namespace, initializing
// bpf tail call map on both directions (see setupInterfaceInRemoteNs), and configuring the interface.
func SetupL2Interface(ifNameInPod string, podResources map[string][]string, network *networkv1alpha1.Network,
	intf *networkv1alpha1.NetworkInterface, ep *models.EndpointChangeRequest, dc dhcp.DHCPClient) (err_ error) {
	cfg, err := getInterfaceConfiguration(intf, network)
	if err != nil {
		err_ = fmt.Errorf("failed to get a valid interface configuration: %v", err)
		return
	}
	log.Debugf("L2 interface configuration: %+v", cfg)
	parentDevLink, err := netlink.LinkByName(cfg.ParentInterfaceName)
	if err != nil {
		err_ = fmt.Errorf("failed to lookup parent interface %q: %v", cfg.ParentInterfaceName, err)
		return
	}
	// TODO(yfshen): get MTU information from interface CR.
	cfg.MTU = parentDevLink.Attrs().MTU

	var srcIfName string
	macvtapIfNames, isMacvtap := podResources[macvtapResourceName(cfg.ParentInterfaceName)]
	if !isMacvtap {
		srcIfName = Endpoint2TempRandIfName()
		macvlan, err := createMacvlanChild(srcIfName, parentDevLink.Attrs().Index)
		if err != nil {
			err_ = err
			return
		}
		defer func() {
			if err_ != nil {
				if err = netlink.LinkDel(macvlan); err != nil {
					log.WithError(err).WithField(logfields.Macvlan, macvlan.Name).Warn("failed to clean up macvlan")
				}
			}
		}()
		ep.DeviceType = multinicep.EndpointDeviceMACVLAN
	} else {
		if len(macvtapIfNames) != 1 {
			err_ = fmt.Errorf("found %d macvtap interface for parent interface %q. Only single macvtap interface is supported.", len(macvtapIfNames), cfg.ParentInterfaceName)
			return
		}
		srcIfName = macvtapIfNames[0]
		ep.DeviceType = multinicep.EndpointDeviceMACVTAP
	}

	log.WithFields(logrus.Fields{
		logfields.DeviceType:     ep.DeviceType,
		logfields.InterfaceInPod: ifNameInPod,
		logfields.NetNSName:      ep.NetworkNamespace,
		"sourceInterface":        srcIfName,
		"parentInterface":        cfg.ParentInterfaceName,
	}).Debug("Set up L2 interface")

	link, err := netlink.LinkByName(srcIfName)
	if err != nil {
		err_ = fmt.Errorf("failed to lookup interface %q: %v", srcIfName, err)
		return
	}

	if err = DisableRpFilter(srcIfName); err != nil {
		err_ = err
		return
	}

	netNs, err := ns.GetNS(ep.NetworkNamespace)
	if err != nil {
		err_ = fmt.Errorf("failed to open netns %q: %v", ep.NetworkNamespace, err)
		return
	}
	defer netNs.Close()

	// Move the link to the target network namespace.
	if err = netlink.LinkSetNsFd(link, int(netNs.Fd())); err != nil {
		err_ = fmt.Errorf("failed to move link %q to netns %q: %v", link.Attrs().Name, netNs.Path(), err)
		return
	}

	m, err := setupInterfaceInRemoteNs(netNs, srcIfName, ifNameInPod, true)
	if err != nil {
		err_ = fmt.Errorf("unable to setup link %q in remote netns: %v", link.Attrs().Name, err)
		return
	}
	defer m.Close()

	mapID, err := m.ID()
	if err != nil {
		err_ = fmt.Errorf("failed to get map ID: %w", err)
		return
	}

	dhcpResp, err := configureDHCPInfo(network, cfg, dc, ep.NetworkNamespace, ifNameInPod, ep.ContainerID)
	if err != nil {
		err_ = fmt.Errorf("failed to query DHCP information: %v", err)
		return
	}

	if err := configureInterface(cfg, netNs, ifNameInPod); err != nil {
		err_ = fmt.Errorf("failed to configure interface: %v", err)
		return
	}

	populateInterfaceStatus(intf, network, cfg, dhcpResp)

	// Update the endpoint addressing after the macvlan interface is configured.
	ep.Addressing.IPV4 = cfg.IPV4Address.IP.String()
	ep.Mac = cfg.MacAddress.String()
	ep.HostMac = parentDevLink.Attrs().HardwareAddr.String()
	ep.InterfaceName = srcIfName
	ep.InterfaceIndex = int64(link.Attrs().Index)
	ep.InterfaceNameInPod = ifNameInPod
	ep.ParentDeviceIndex = int64(parentDevLink.Attrs().Index)
	ep.ParentDeviceName = parentDevLink.Attrs().Name
	ep.DatapathMapID = int64(mapID)
	ep.ExternalDHCP4 = dhcpResp != nil

	return
}

// DeleteMacvlanInRemoteNs deletes the macvlan interface in the remote network namespace.
func DeleteMacvlanInRemoteNs(ifName, nsPath string) error {
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
func SetupNetworkRoutes(ifNameInPod string, intf *networkv1alpha1.NetworkInterface, nsPath string,
	isDefaultInterface bool, podNetworkMTU int) error {
	log.WithFields(logrus.Fields{
		logfields.InterfaceInPod: ifNameInPod,
		logfields.NetNSName:      nsPath,
		logfields.MTU:            podNetworkMTU,
		"network":                intf.Spec.NetworkName,
		"isDefaultInterface":     isDefaultInterface,
	}).Debug("Set up network")

	var (
		destCIDRs []*net.IPNet
		gw        *net.IP
		err       error
		mtu       int
	)

	if intf.Spec.NetworkName == networkv1alpha1.DefaultNetworkName {
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

		if err := addRoutes(destCIDRs, gw, l, mtu); err != nil {
			return err
		}
		// No need to re-configure the default route for pod-network.
		if isDefaultInterface && intf.Spec.NetworkName != networkv1alpha1.DefaultNetworkName {
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

func configureDHCPInfo(network *networkv1alpha1.Network, cfg *interfaceConfiguration, dc dhcp.DHCPClient, podNS, podIface, containerID string) (*dhcp.DHCPResponse, error) {
	if network.Spec.ExternalDHCP4 == nil || *network.Spec.ExternalDHCP4 == false {
		// No DHCP is required when externalDHCP4 is false or not set
		return nil, nil
	}

	parentInterface, err := network.InterfaceName()
	if err != nil {

		return nil, fmt.Errorf("failed to configue dhcp info for %s: %s", network.Name, err)
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

func isDNSConfigured(network *networkv1alpha1.Network) bool {
	if network.Spec.DNSConfig == nil {
		return false
	}

	config := *network.Spec.DNSConfig
	if len(config.Nameservers) > 0 || len(config.Searches) > 0 {
		return true
	}
	return false
}

func isStaticNetwork(network *networkv1alpha1.Network) bool {
	// If Network has any static information, the network is considered static.
	routesConfigured := len(network.Spec.Routes) > 0
	gatewayConfigured := network.Spec.Gateway4 != nil && *(network.Spec.Gateway4) != ""
	dnsConfigured := isDNSConfigured(network)

	return routesConfigured || gatewayConfigured || dnsConfigured
}

func populateInterfaceStatus(intf *networkv1alpha1.NetworkInterface, network *networkv1alpha1.Network, cfg *interfaceConfiguration, dhcpResp *dhcp.DHCPResponse) {
	// Update the interface status after IP and MAC address are configured successfully.
	intf.Status.IpAddresses = []string{cfg.IPV4Address.String()}
	intf.Status.MacAddress = cfg.MacAddress.String()

	if isStaticNetwork(network) {
		intf.Status.Routes = network.Spec.Routes
		intf.Status.Gateway4 = network.Spec.Gateway4
		intf.Status.DNSConfig = network.Spec.DNSConfig
		return
	}
	if dhcpResp == nil {
		return
	}
	intf.Status.Routes = dhcpResp.Routes
	intf.Status.Gateway4 = dhcpResp.Gateway4
	intf.Status.DNSConfig = dhcpResp.DNSConfig
}
