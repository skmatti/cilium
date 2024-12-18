package controller

import (
	"context"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	networkv1 "k8s.io/cloud-provider-gcp/crd/apis/network/v1"
)

func (r *NetworkReconciler) updateMultiNetworkIPAM(ctx context.Context, network *networkv1.Network) error {
	if network.Spec.ExternalDHCP4 != nil && *network.Spec.ExternalDHCP4 {
		r.Log.Info("external DHCP enabled for network, no need to update IPAM maps")
		return nil
	}
	node := &corev1.Node{}
	if err := r.Get(ctx, types.NamespacedName{Name: r.NodeName}, node); err != nil {
		return err
	}
	if err := r.IPAMMgr.UpdateMultiNetworkIPAMAllocators(node.Annotations); err != nil {
		return err
	}
	r.Log.Info("multi-net IPAM map is updated successfully")
	return nil
}
