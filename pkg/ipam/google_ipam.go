package ipam

import "net"

// NewHostScopeAllocator is a wrapper over newHostScopeAllocator.
func NewHostScopeAllocator(n *net.IPNet) Allocator {
	return newHostScopeAllocator(n)
}
