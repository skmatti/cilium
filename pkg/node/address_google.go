//go:build linux

package node

import (
	"fmt"
	"net"

	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
	"github.com/vishvananda/netlink"
)

// FirstV4GlobalAddr returns the first IPv4 global address of an interface.
// Public IPs are preferred over private ones.
// If no IP is found on the given interface, all the interfaces are checked.
// Return error when no IP is found.
// See firstGlobalV4Addr for more details.
func FirstV4GlobalAddr(intf string) (net.IP, error) {
	return firstGlobalAddr(intf, nil, netlink.FAMILY_V4, true)
}

// FirstV4GlobalAddrOnInf returns the first global unicast IPv4 address of an interface.
// Returns an empty string and an error if no IPv4 is found on the given interface.
func FirstV4GlobalAddrOnInf(intf string) (string, error) {
	if intf == "" || intf == "undefined" {
		return "", fmt.Errorf("interface not defined")
	}

	link, err := safenetlink.LinkByName(intf)
	if err != nil {
		return "", fmt.Errorf("failed to get link by name for interface: %s with error: %v", intf, err)
	}

	addrs, err := safenetlink.AddrList(link, netlink.FAMILY_V4)
	if err != nil {
		return "", fmt.Errorf("failed to get addresses for link for interface %s: %v", intf, err)
	}

	for _, addr := range addrs {
		if addr.IP.IsGlobalUnicast() {
			return addr.IP.String(), nil
		}
	}

	return "", fmt.Errorf("no global IPv4 address found on interface %s", intf)
}
