package cmd

import (
	"github.com/cilium/cilium/pkg/gke/multinic/types"
	"github.com/cilium/cilium/pkg/ipam"
	"github.com/cilium/cilium/pkg/node"

	networkv1 "gke-internal.googlesource.com/anthos-networking/apis/v2/network/v1"
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
	existingAllocators := d.ipam.MultiNetworkAllocators
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
