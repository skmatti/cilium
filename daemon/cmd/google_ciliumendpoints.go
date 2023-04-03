package cmd

import (
	"context"
	"fmt"

	multiniccep "github.com/cilium/cilium/pkg/gke/multinic/ciliumendpoint"
	cilium_v2a1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
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

func (d *Daemon) cleanStaleCEPinCESWhenMultiNIC(
	ctx context.Context,
	eps localEndpointCache,
	ciliumClient ciliumv2.CiliumV2Interface,
	objs []interface{}) error {
	ipv4Endpoints, ipv6Endpoints := d.buildIPEndpointMaps()
	for _, cesObj := range objs {
		ces, ok := cesObj.(*cilium_v2a1.CiliumEndpointSlice)
		if !ok {
			return fmt.Errorf("unexpected object type returned from ciliumendpointslice store: %T", cesObj)
		}
		for _, cep := range ces.Endpoints {
			v4Exists := false
			v6Exists := false
			for _, a := range cep.Networking.Addressing {
				if a.IPV4 != "" {
					_, v4Exists = ipv4Endpoints[a.IPV4]
				}
				if a.IPV6 != "" {
					_, v6Exists = ipv6Endpoints[a.IPV6]
				}
				if v4Exists || v6Exists {
					break
				}
			}
			if cep.Networking.NodeIP == node.GetCiliumEndpointNodeIP() && !v4Exists && !v6Exists {
				d.deleteCiliumEndpoint(ctx, ces.Namespace, cep.Name, nil, ciliumClient, eps, true)
			}
		}
	}
	return nil
}

func (d *Daemon) buildIPEndpointMaps() (map[string]struct{}, map[string]struct{}) {
	ipv4Endpoints := map[string]struct{}{}
	ipv6Endpoints := map[string]struct{}{}
	for _, ep := range d.endpointManager.GetEndpoints() {
		ipv4Endpoints[string(ep.IPv4Address().IP())] = struct{}{}
		ipv6Endpoints[string(ep.IPv6Address().IP())] = struct{}{}
	}
	return ipv4Endpoints, ipv6Endpoints
}
