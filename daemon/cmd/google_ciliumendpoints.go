package cmd

import (
	"context"
	"fmt"

	multiniccep "github.com/cilium/cilium/pkg/gke/multinic/ciliumendpoint"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/typed/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/types"
	"github.com/cilium/cilium/pkg/node"
)

func (d *Daemon) cleanStaleCEPWhenMultiNIC(ctx context.Context,
	eps localEndpointCache,
	ciliumClient ciliumv2.CiliumV2Interface,
	cep *types.CiliumEndpoint) error {
	podName, err := multiniccep.GetPodNameFromCEP(cep)
	if err != nil {
		return fmt.Errorf("cannot get pod name from CiliumEndpoint: %w", err)
	}

	if cep.Networking.NodeIP == node.GetCiliumEndpointNodeIP() && len(eps.LookupEndpointsByPodName(cep.Namespace+"/"+podName)) == 0 {
		d.deleteCiliumEndpoint(ctx, cep.Namespace, cep.Name, &cep.ObjectMeta.UID, ciliumClient, eps,
			false)
	}
	return nil
}
