package controller

import (
	"context"
	"fmt"

	networkv1 "github.com/GoogleCloudPlatform/gke-networking-api/apis/network/v1"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/gke/multinic/types"
	"github.com/cilium/cilium/pkg/node"
)

func (r *NetworkReconciler) updateMultiNetworkIPAM(ctx context.Context, network *networkv1.Network) error {
	if network.Spec.ExternalDHCP4 != nil && *network.Spec.ExternalDHCP4 {
		r.Log.Info("external DHCP enabled for network, no need to update IPAM maps")
		return nil
	}
	node, err := r.LocalNode(ctx)
	if err != nil {
		return fmt.Errorf("failed to fetch latest local node while updating multinetworking IPAM: %v", err)
	}
	if err := r.IPAMMgr.UpdateMultiNetworkIPAMAllocators(node.Annotations); err != nil {
		return err
	}
	r.Log.Info("multi-net IPAM map is updated successfully")
	return nil
}

// SetupMultiNetworkingIPAMAllocators performs the following actions:
// 1. Initialises the IPAM allocators for the networks present on the node that is derived from the node annotations.
// 2. Allocates the IPs associated with the given endpoints inside the allocators created in step 1.
func (r *NetworkReconciler) SetupMultiNetworkingIPAMAllocators(mnwIPAMMgr types.MultiNetworkIPAMManager, endpoints []*endpoint.Endpoint) error {
	if err := mnwIPAMMgr.UpdateMultiNetworkIPAMAllocators(node.GetAnnotations()); err != nil {
		return fmt.Errorf("failed to initialize multi-network allocators: %v", err)
	}
	if err := mnwIPAMMgr.PreAllocateIPsForRestoredMultiNICEndpoints(endpoints); err != nil {
		return fmt.Errorf("failed to pre-allocate IPs in multinetworking IPAM allocators for restored endpoints: %v", err)
	}
	return nil
}
