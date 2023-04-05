package ipam

import "net"

// NewHostScopeAllocator is a wrapper over newHostScopeAllocator.
func NewHostScopeAllocator(n *net.IPNet) Allocator {
	return newHostScopeAllocator(n)
}

// DeriveGatewayIP is a wrapper over deriveGatewayIP. This returns the first IP in the CIDR as the gateway.
func DeriveGatewayIP(cidr string) string {
	return deriveGatewayIP(cidr, 1)
}
