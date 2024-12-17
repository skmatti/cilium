package endpointcleanup

import (
	"context"
	"fmt"

	multiniccep "github.com/cilium/cilium/pkg/gke/multinic/ciliumendpoint"
	cilium_v2a1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/types"
	"github.com/cilium/cilium/pkg/node"
)

func (c *cleanup) cleanStaleCEPWhenMultiNIC(ctx context.Context,
	eps localEndpointCache,
	cep *types.CiliumEndpoint) error {
	podName, err := multiniccep.GetPodNameFromCEP(cep)
	if err != nil {
		return fmt.Errorf("cannot get pod name from CiliumEndpoint: %w", err)
	}

	if cep.Networking.NodeIP == node.GetCiliumEndpointNodeIP() && len(eps.LookupEndpointsByPodName(cep.Namespace+"/"+podName)) == 0 {
		c.deleteCiliumEndpoint(ctx, cep.Namespace, cep.Name, &cep.ObjectMeta.UID)
	}
	return nil
}

func (c *cleanup) cleanStaleCEPinCESWhenMultiNIC(
	ctx context.Context,
	eps localEndpointCache,
	objs []*cilium_v2a1.CiliumEndpointSlice) error {
	ipv4Endpoints, ipv6Endpoints := c.buildIPEndpointMaps()
	for _, cesObj := range objs {
		for _, cep := range cesObj.Endpoints {
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
				c.deleteCiliumEndpoint(ctx, cesObj.Namespace, cep.Name, nil)
			}
		}
	}
	return nil
}

func (c *cleanup) buildIPEndpointMaps() (map[string]struct{}, map[string]struct{}) {
	ipv4Endpoints := map[string]struct{}{}
	ipv6Endpoints := map[string]struct{}{}
	for _, ep := range c.endpointsCache.GetEndpoints() {
		ipv4Endpoints[string(ep.IPv4.String())] = struct{}{}
		ipv6Endpoints[string(ep.IPv6.String())] = struct{}{}
	}
	return ipv4Endpoints, ipv6Endpoints
}
