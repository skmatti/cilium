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
	// This is to handle static IP endpoints.
	// We do not have a way to check if endpoints were assigned an IP statically.
	// TODO(b/264624818) - Update this once design around IPAM mode in network object is finalised.
	if len(d.ipam.MultiNetworkAllocators) == 0 {
		ep.Logger(daemonSubsys).Warning("endpoint is multi-nic but no allocators were found to occupy its IP address, may be endpoint IP is static")
		return nil
	}
	reserved := false
	for _, alloc := range d.ipam.MultiNetworkAllocators {
		// TODO - Add support for IPv6 in future.
		_, err := alloc.Allocate(ep.IPv4.IP(), ep.K8sPodName)
		if err == nil {
			reserved = true
			ep.Logger(daemonSubsys).Info("successfully restored multi-nic endpoint IP")
			break
		}
	}
	if !reserved {
		return fmt.Errorf("could not find an allocator to allocate the IP of the multi-nic endpoint")
	}
	return nil
}
