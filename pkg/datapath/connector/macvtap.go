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
	"fmt"
	"net"

	"github.com/cilium/cilium/api/v1/models"
	multinicv1alpha1 "github.com/cilium/cilium/pkg/gke/apis/multinic/v1alpha1"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"k8s.io/apimachinery/pkg/types"
)

const (
	kubevirtMacvtapResourcePrefix = "macvtap.network.kubevirt.io"
)

// interfaceConfiguration holds network properties needed to configure the interface.
type interfaceConfiguration struct {
	// IPV4Address is in CIDR annotation and holds single IPV4 address applied to the macvtap interface.
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
			return nil, fmt.Errorf("IPV6 is not supported for macvtap interface")
		}
		return &net.IPNet{
			IP:   ip,
			Mask: ipNet.Mask,
		}, nil
	}
	// Check if the IP address string is in IP format without subnet lentgh
	ip = net.ParseIP(addr)
	if ip == nil {
		return nil, fmt.Errorf("failed to parse IP %q", addr)
	}
	var mask net.IPMask
	if isIPV6(ip) {
		return nil, fmt.Errorf("IPV6 is not supported for macvtap interface")
	}
	mask = net.CIDRMask(32, 32)
	return &net.IPNet{
		IP:   ip,
		Mask: mask,
	}, nil
}

// getInterfaceConfiguration returns interfaceConfiguration which is needed to configure the macvtap interface.
// The function also enforces some necessary checks of the configuration and returns a proper error message.
func getInterfaceConfiguration(intf *multinicv1alpha1.NetworkInterface, network *multinicv1alpha1.Network) (*interfaceConfiguration, error) {
	intfID := types.NamespacedName{
		Name:      intf.Name,
		Namespace: intf.Namespace,
	}
	if len(intf.Spec.IpAddresses) != 1 {
		return nil, fmt.Errorf("found %d IP addresses in the interface CR %q. Only single IPv4 address is supported for macvtap interface.", len(intf.Spec.IpAddresses), intfID.String())
	}
	if intf.Spec.MacAddress == nil {
		return nil, fmt.Errorf("no Mac address is found in the interface CR %q", intfID.String())
	}
	if network.Spec.NodeInterfaceMatcher.InterfaceName == nil {
		return nil, fmt.Errorf("parent interface name is not found in the network CR %q", network.Name)
	}

	var cfg interfaceConfiguration
	ipNet, err := parseIPSubnet(intf.Spec.IpAddresses[0])
	if err != nil {
		return nil, fmt.Errorf("failed to get a valid IP in the interface CR %q: %v", intfID.String(), err)
	}
	cfg.IPV4Address = ipNet

	hardwareAddr, err := net.ParseMAC(*intf.Spec.MacAddress)
	if err != nil {
		return nil, fmt.Errorf("unable to parse MAC in the interface CR %q: %v", intfID.String(), err)
	}
	cfg.MacAddress = hardwareAddr

	cfg.ParentInterfaceName = *network.Spec.NodeInterfaceMatcher.InterfaceName
	if cfg.ParentInterfaceName == "" {
		return nil, fmt.Errorf("parent interface name is empty in the network CR %q", network.Name)
	}
	return &cfg, nil
}

func applyIPToLink(ipAddr *net.IPNet, l netlink.Link) error {
	log.WithFields(logrus.Fields{
		logfields.IPAddr:  ipAddr,
		logfields.Macvtap: l.Attrs().Name,
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
		logfields.Macvtap: l.Attrs().Name,
	}).Debug("Configuring link mac address")

	if err := netlink.LinkSetHardwareAddr(l, macAddr); err != nil {
		return fmt.Errorf("failed to add MAC addr %q to %q: %v", macAddr.String(), l.Attrs().Name, err)
	}
	return nil
}

// configureInterface applies IP configuration to the target interface with the provided interface configuration,
// and returns the list of applied IP addresses and mac address for status updating.
func configureInterface(cfg *interfaceConfiguration, netNs ns.NetNS, ifName string) error {
	if err := netNs.Do(func(_ ns.NetNS) error {
		l, err := netlink.LinkByName(ifName)
		if err != nil {
			return fmt.Errorf("failed to lookup interface %q: %v", ifName, err)
		}
		if err = netlink.LinkSetMTU(l, cfg.MTU); err != nil {
			return fmt.Errorf("unable to set MTU to %q: %v", l.Attrs().Name, err)
		}
		if err := applyMACToLink(cfg.MacAddress, l); err != nil {
			return fmt.Errorf("failed to apply mac address to %q: %v", l.Attrs().Name, err)
		}
		if err := applyIPToLink(cfg.IPV4Address, l); err != nil {
			return fmt.Errorf("failed to apply IP configuration: %v", err)
		}

		if err := netlink.LinkSetUp(l); err != nil {
			return fmt.Errorf("failed to set link %q UP: %v", ifName, err)
		}
		return nil
	}); err != nil {
		return fmt.Errorf("unable to configure interface %q in container namespace: %s", ifName, err)
	}

	return nil
}

// HasMacvtapDevices checks if macvtap devices exist for the given resource name.
func HasMacvtapDevices(name string, podResources map[string][]string) bool {
	_, ok := podResources[macvtapResourceName(name)]
	return ok
}

// macvtapResourceName returns the macvtap resource name with the prefix.
func macvtapResourceName(name string) string {
	return kubevirtMacvtapResourcePrefix + "/" + name
}

// RevertMacvtapSetup performs operations to revert macvtap setup done in SetupMacvtapChild(), including
// removing bpf filter and clsact qdisc, renaming and moving link back to the globacl namespace.
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

// SetupMacvtapChild looks for the created macvtap link, moves it to the given network namespace, and finally
// initializes it including ebpf map load on both direction (see setupInterfaceInRemoteNs).
func SetupMacvtapChild(ifNameInPod string, podResources map[string][]string, network *multinicv1alpha1.Network,
	intf *multinicv1alpha1.NetworkInterface, ep *models.EndpointChangeRequest) error {
	cfg, err := getInterfaceConfiguration(intf, network)
	if err != nil {
		return fmt.Errorf("failed to get a valid interface configuration: %v", err)
	}

	parentDevLink, err := netlink.LinkByName(cfg.ParentInterfaceName)
	if err != nil {
		return fmt.Errorf("failed to lookup interface %q: %v", cfg.ParentInterfaceName, err)
	}

	macvtapIfNames, ok := podResources[macvtapResourceName(cfg.ParentInterfaceName)]
	if !ok {
		return fmt.Errorf("no macvtap interface found for parent interface %q", cfg.ParentInterfaceName)
	}
	if len(macvtapIfNames) != 1 {
		return fmt.Errorf("found %d macvtap interface for parent interface %q. Only single macvtap interface is supported.", len(macvtapIfNames), cfg.ParentInterfaceName)
	}
	macvtapIfName := macvtapIfNames[0]
	log.WithField(logfields.Macvtap, macvtapIfName).Debug("Found macvtap interface in host namespace")

	err = DisableRpFilter(macvtapIfName)
	if err != nil {
		return err
	}

	macvtapLink, err := netlink.LinkByName(macvtapIfName)
	if err != nil {
		return fmt.Errorf("failed to lookup interface %q: %v", macvtapIfName, err)
	}
	intfIndex := int64(macvtapLink.Attrs().Index)

	// TODO(yfshen): get MTU information from interface CR.
	cfg.MTU = parentDevLink.Attrs().MTU

	netNs, err := ns.GetNS(ep.NetworkNamespace)
	if err != nil {
		return fmt.Errorf("failed to open netns %q: %v", ep.NetworkNamespace, err)
	}
	defer netNs.Close()

	// Move the macvtap link to the target network namespace.
	if err = netlink.LinkSetNsFd(macvtapLink, int(netNs.Fd())); err != nil {
		return fmt.Errorf("failed to move macvtap link %q to netns %q: %v", macvtapLink.Attrs().Name, netNs.Path(), err)
	}

	m, err := setupInterfaceInRemoteNs(netNs, macvtapIfName, ifNameInPod, true)
	if err != nil {
		return fmt.Errorf("unable to setup macvtap in remote netns: %v", err)
	}
	defer m.Close()

	mapID, err := m.ID()
	if err != nil {
		return fmt.Errorf("failed to get map ID: %w", err)
	}

	if err := configureInterface(cfg, netNs, ifNameInPod); err != nil {
		return fmt.Errorf("failed to configure macvtap interface: %v", err)
	}

	// Update the interface status after IP and MAC address are configured successfully.
	intf.Status.IpAddresses = []string{cfg.IPV4Address.String()}
	intf.Status.MacAddress = cfg.MacAddress.String()

	// Update the endpoint addressing after the macvtap interface is configured.
	ep.Addressing.IPV4 = cfg.IPV4Address.IP.String()
	ep.Mac = cfg.MacAddress.String()
	ep.HostMac = parentDevLink.Attrs().HardwareAddr.String()
	ep.InterfaceName = macvtapIfName
	ep.InterfaceIndex = intfIndex
	ep.InterfaceNameInPod = ifNameInPod
	ep.ParentDeviceIndex = int64(parentDevLink.Attrs().Index)
	ep.ParentDeviceName = parentDevLink.Attrs().Name
	ep.DatapathMapID = int64(mapID)

	return nil
}
