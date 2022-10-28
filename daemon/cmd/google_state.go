package cmd

import (
	"fmt"

	"github.com/cilium/cilium/pkg/endpoint"
)

func (d *Daemon) allocateIPsIfMultiNICEndpoint(ep *endpoint.Endpoint) error {
	if !ep.IsMultiNIC() || ep.ExternalDHCPEnabled() {
		return nil
	}
	d.ipam.MultiNetworkAllocatorMutex.Lock()
	defer d.ipam.MultiNetworkAllocatorMutex.Unlock()
	reserved := false
	for _, alloc := range d.ipam.MultiNetworkAllocators {
		// TODO - Add support for IPv6 in future.
		_, err := alloc.Allocate(ep.IPv4.IP(), ep.K8sPodName)
		if err == nil {
			reserved = true
			break
		}
	}
	if !reserved {
		return fmt.Errorf("could not find an allocator to allocate the IP of the multi-nic endpoint")
	}
	return nil
}
