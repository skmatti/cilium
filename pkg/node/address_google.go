package node

import (
	"net"

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
