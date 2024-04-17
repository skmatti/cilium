package eventcache

import (
	"reflect"

	eventcachetypes "github.com/cilium/cilium/pkg/gke/eventcache/types"
	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"golang.org/x/exp/maps"
)

func (c *cache) ensurePortsEndpoints(id eventcachetypes.ServiceID) {
	if c.ports[id] == nil {
		c.ports[id] = make(map[loadbalancer.L4Addr]*portEntry)
	}
	if c.endpoints[id] == nil {
		c.endpoints[id] = make(map[loadbalancer.L3n4Addr]*endpointEntry)
	}
}

func (c *cache) currentPorts(id eventcachetypes.ServiceID) map[loadbalancer.FEPortName]*loadbalancer.L4Addr {
	svc, ok := c.services[id]
	if !ok {
		return nil
	}
	return svc.Ports
}

func portMapToSet(portMap map[loadbalancer.FEPortName]*loadbalancer.L4Addr) map[loadbalancer.L4Addr]struct{} {
	ans := make(map[loadbalancer.L4Addr]struct{})
	for _, v := range portMap {
		ans[*v] = struct{}{}
	}
	return ans
}

func noPendingEvents(times *kubeAPITimes) bool {
	return times.add.IsZero() && times.update.IsZero() && times.del.IsZero()
}

// areServicesEqual returns false when one pointer is nil and the other is not,
// or when Ports maps are different.
func areServicesEqual(old, n *k8s.Service) bool {
	// TODO(b/324058974) Consider a more thorough comparison.
	if old == nil || n == nil {
		return old == n
	}
	return reflect.DeepEqual(old.Ports, n.Ports)
}

// areServicesFromBothSourcesEqual behaves differently from areServicesEqual because before it compares ports,
// it converts the map with ports to a slice, ignoring map keys, that is, port names.
func (h *HybridCache) areServicesFromBothSourcesEqual(id eventcachetypes.ServiceID) bool {
	return areServicesFromBothSourcesEqual((*k8s.Service)(h.cacheFrom[eventcachetypes.KubeAPI].services[id]), (*k8s.Service)(h.cacheFrom[eventcachetypes.TDxDS].services[id]))
}

func areServicesFromBothSourcesEqual(fromKubeAPI, fromTDxDS *k8s.Service) bool {
	if fromKubeAPI == nil || fromTDxDS == nil {
		return fromKubeAPI == fromTDxDS
	}
	return maps.Equal(portMapToSet(fromKubeAPI.Ports), portMapToSet(fromTDxDS.Ports))
}

func (h *HybridCache) arePortsFromBothSourcesEqual(id eventcachetypes.ServiceID, p loadbalancer.L4Addr) bool {
	return reflect.DeepEqual(h.cacheFrom[eventcachetypes.KubeAPI].ports[id][p], h.cacheFrom[eventcachetypes.TDxDS].ports[id][p])
}

func (h *HybridCache) areEndpointsFromBothSourcesEqual(id eventcachetypes.ServiceID, e loadbalancer.L3n4Addr) bool {
	KubeAPIEndpoint := h.cacheFrom[eventcachetypes.KubeAPI].endpoints[id][e]
	TDEndpoint := h.cacheFrom[eventcachetypes.TDxDS].endpoints[id][e]
	if KubeAPIEndpoint == nil || TDEndpoint == nil {
		return KubeAPIEndpoint == TDEndpoint
	}
	return true // TODO(b/350656592): The only field of the type endpoint is the `terminating` bool, which is not populated in xDS, so we always return true when both pointers are non-nil.
}
