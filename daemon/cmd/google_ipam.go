package cmd

import (
	"fmt"
	"net"

	"github.com/cilium/cilium/pkg/gke/multinic/types"
	"github.com/cilium/cilium/pkg/ipam"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/ipam/service/ipallocator"

	networkv1 "k8s.io/cloud-provider-gcp/crd/apis/network/v1"
)

// UpdateMultiNetworkIPAMAllocators updates the daemon's multi-network IPAM allocators.
func (d *Daemon) UpdateMultiNetworkIPAMAllocators(annotations map[string]string) error {
	d.ipam.MultiNetworkAllocatorMutex.Lock()
	defer d.ipam.MultiNetworkAllocatorMutex.Unlock()
	mns, ok := annotations[networkv1.MultiNetworkAnnotationKey]
	if !ok {
		return nil
	}
	nws, err := types.BuildMultiNetworkCIDRs(mns)
	if err != nil {
		return err
	}
	node.SetAnnotations(annotations)
	node.SetPodNetworks(nws)
	existingAllocators := d.ipam.MultiNetworkAllocators
	if existingAllocators == nil {
		existingAllocators = map[string]ipam.Allocator{}
	}
	// Delete the allocator of the network that is not present anymore.
	for n := range existingAllocators {
		if _, ok := nws[n]; !ok {
			delete(existingAllocators, n)
		}
	}
	// Create and add new allocators for networks that are new.
	for n, c := range nws {
		if _, ok := existingAllocators[n]; !ok {
			existingAllocators[n] = ipam.NewHostScopeAllocator(c.IPNet)
		}
	}
	d.ipam.MultiNetworkAllocators = existingAllocators
	log.Infof("Updated multi network IPAM allocators: %+v", d.ipam.MultiNetworkAllocators)
	return nil
}

func (d *Daemon) ReserveGatewayIP(network *networkv1.Network) error {
	if network == nil || networkv1.IsDefaultNetwork(network.Name) {
		return nil
	}
	if network.Spec.Type != networkv1.L3NetworkType {
		return nil
	}
	d.ipam.MultiNetworkAllocatorMutex.Lock()
	defer d.ipam.MultiNetworkAllocatorMutex.Unlock()
	allocator, ok := d.ipam.MultiNetworkAllocators[network.Name]
	if !ok {
		return fmt.Errorf("allocator for network %s is not present, cannot reserve a gateway IP", network.Name)
	}
	nwCIDRs := node.GetPodNetworks()
	cidr, ok := nwCIDRs[network.Name]
	if !ok {
		return fmt.Errorf("missing cidr for network %s, cannot reserve a gateway IP", network.Name)
	}
	// Derive and reserve gateway IP for network.
	gwIP := ipam.DeriveGatewayIP(cidr.String())
	log.Infof("reserving gateway IP %s for network %s", gwIP, network.Name)
	_, err := allocator.Allocate(net.ParseIP(gwIP), "")
	if err != nil {
		if err == ipallocator.ErrAllocated {
			log.Infof("gateway IP for network %s is already reserved, returning.", network.Name)
		} else {
			return fmt.Errorf("error while reserving gateway IP for network %s: %v", network.Name, err)
		}
	}
	return nil
}

func (d *Daemon) AllocateIP(ip, owner string) error {
	if ip == "" {
		return fmt.Errorf("failed to allocate IP, IP cannot be empty string")
	}
	d.ipam.MultiNetworkAllocatorMutex.Lock()
	defer d.ipam.MultiNetworkAllocatorMutex.Unlock()
	// A no-op if there are no allocators to allocate the IP because of backward compatibility for kubevirt
	// to handle cases like static IP endpoints. We do not have a way to check if endpoints were assigned an IP statically.
	// TODO(b/264624818) - Update this once design around IPAM mode in network object is finalised.
	if len(d.ipam.MultiNetworkAllocators) == 0 {
		return nil
	}
	reserved := false
	for _, alloc := range d.ipam.MultiNetworkAllocators {
		// TODO - Add support for IPv6 in future.
		_, err := alloc.Allocate(net.ParseIP(ip), owner)
		if err == nil || err == ipallocator.ErrAllocated {
			reserved = true
			break
		}
	}
	if !reserved {
		return fmt.Errorf("could not find an allocator to allocate the IP %s", ip)
	}
	return nil
}
