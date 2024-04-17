package k8s

import (
	"net"
	"net/netip"

	eventcachetypes "github.com/cilium/cilium/pkg/gke/eventcache/types"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/lock"
)

const (
	OneNetworkLabelKey   = "networking.gke.io/service-proxy-name"
	OneNetworkLabelValue = "experimental"
)

// Hybrid Cache is a cache for services and endpoints, and it is called hybrid because it integrates information from the Traffic Director and the KubeAPI Server.
var HybridCache HybridCacheInterface

// HybridCacheInterface is the API of the package pkg/gke/eventcache. The interface is included here to avoid a circular import.
type HybridCacheInterface interface {
	UpdateService(id eventcachetypes.ServiceID, service *Service, src eventcachetypes.Source, swg *lock.StoppableWaitGroup)
	DeleteService(id eventcachetypes.ServiceID, src eventcachetypes.Source, swg *lock.StoppableWaitGroup)
	DeleteEndpoint(id eventcachetypes.ServiceID, ipPort loadbalancer.L3n4Addr, src eventcachetypes.Source, swg *lock.StoppableWaitGroup)
	UpdateEndpoint(id eventcachetypes.ServiceID, ipPort loadbalancer.L3n4Addr, terminating bool, src eventcachetypes.Source, swg *lock.StoppableWaitGroup)
	UpdateManyEndpoints(id eventcachetypes.ServiceID, newEndpoints *Endpoints, src eventcachetypes.Source, swg *lock.StoppableWaitGroup)
}

func findIPv4(ips []net.IP) net.IP {
	for _, ip := range ips {
		if ans := ip.To4(); ans != nil {
			return ans
		}
	}
	return nil
}

func updateOrDeleteServiceInHybrid(svcID ServiceID, oldService, newService *Service, swg *lock.StoppableWaitGroup) {
	// Detect 1N-label removal, which is not service deletion from k8s perspective, but it is one from Hybrid Cache perspective.
	if !hasEnhancedLabelSet(newService.Labels) && oldService != nil && hasEnhancedLabelSet(oldService.Labels) {
		log.Infof("Deleting the service %s(%v) from Hybrid Cache because the enhanced-services label got removed.", svcID, newService.FrontendIPs)
		deleteServiceInHybrid(svcID, oldService, swg)
		return
	}

	if HybridCache == nil || len(newService.FrontendIPs) == 0 {
		return
	}
	if !hasEnhancedLabelSet(newService.Labels) {
		log.Debugf("Not reporting the service %s(%v) to the Hybrid Cache because it's not an enhanced service (%+v).", svcID, newService.FrontendIPs, newService.Labels)
		return
	}

	ip := findIPv4(newService.FrontendIPs)
	if ip == nil {
		log.Debugf("Not reporting the service %s to the Hybrid Cache because it has no IPv4 address %v.", svcID, newService.FrontendIPs)
		return
	}
	addr := netip.AddrFrom4([4]byte(ip))
	HybridCache.UpdateService(eventcachetypes.ServiceID(addr), newService, 0, swg)
}

func deleteServiceInHybrid(svcID ServiceID, service *Service, swg *lock.StoppableWaitGroup) {
	if HybridCache == nil || len(service.FrontendIPs) == 0 {
		return
	}
	if !hasEnhancedLabelSet(service.Labels) {
		log.Debugf("Not deleting the service %s(%v) from the Hybrid Cache because because it's not an enhanced service (%+v).", svcID, service.FrontendIPs, service.Labels)
		return
	}

	ip := findIPv4(service.FrontendIPs)
	if ip == nil {
		log.Debugf("Not deleting the service %s from the Hybrid Cache because it has no IPv4 address %v.", svcID, service.FrontendIPs)
		return
	}
	addr := netip.AddrFrom4([4]byte(ip.To4()))
	HybridCache.DeleteService(eventcachetypes.ServiceID(addr), 0, swg)
}

func updateOrDeleteEndpointsInHybrid(svcID ServiceID, oldService, newService *Service, endpoints *Endpoints, swg *lock.StoppableWaitGroup) {
	// Detect 1N-label removal, which is not service deletion from k8s perspective, but it is one from Hybrid Cache perspective.
	if !hasEnhancedLabelSet(newService.Labels) && oldService != nil && hasEnhancedLabelSet(oldService.Labels) {
		log.Infof("Deleting endpoints %+v from Hybrid Cache because the enhanced-services label for the service %s(%v) got removed.", endpoints.Backends, svcID, newService.FrontendIPs)
		deleteEndpointsInHybrid(svcID, oldService, endpoints, swg)
		return
	}

	if HybridCache == nil {
		return
	}
	if !hasEnhancedLabelSet(newService.Labels) {
		log.Debugf("Not reporting endpoints %+v to the Hybrid Cache for service %s(%v) because it's not an enhanced service (%+v).", endpoints.Backends, svcID, newService.FrontendIPs, newService.Labels)
		return
	}

	svcAddr, ipOK := netip.AddrFromSlice(([]byte)(findIPv4(newService.FrontendIPs)))
	if !ipOK {
		log.Debugf("Not reporting endpoints %+v to the Hybrid Cache for service %s because the service has no IPv4 address %v.", endpoints.Backends, svcID, newService.FrontendIPs)
		return
	}
	HybridCache.UpdateManyEndpoints(eventcachetypes.ServiceID(svcAddr), endpoints, eventcachetypes.KubeAPI, swg)
}

func deleteEndpointsInHybrid(svcID ServiceID, service *Service, endpoints *Endpoints, swg *lock.StoppableWaitGroup) {
	if HybridCache == nil || endpoints == nil {
		return
	}
	if !hasEnhancedLabelSet(service.Labels) {
		log.Debugf("Not deleting endpoints %+v from the Hybrid Cache for service %s(%v) because it's not an enhanced service (%+v).", endpoints.Backends, svcID, service.FrontendIPs, service.Labels)
		return
	}
	backends := endpoints.Backends
	svcAddr, ok := netip.AddrFromSlice(([]byte)(findIPv4(service.FrontendIPs)))
	if !ok {
		log.Debugf("Not deleting endpoints %+v from the Hybrid Cache for service %s because the service has no IPv4 address %v.", endpoints.Backends, svcID, service.FrontendIPs)
		return
	}
	for addrCluster, b := range backends {
		for _, p := range b.Ports {
			ipPort := loadbalancer.NewL3n4Addr(p.Protocol, addrCluster, p.Port, loadbalancer.ScopeExternal)
			HybridCache.DeleteEndpoint(eventcachetypes.ServiceID(svcAddr), *ipPort, eventcachetypes.KubeAPI, swg)
		}
	}
}

func hasEnhancedLabelSet(labels map[string]string) bool {
	return labels[OneNetworkLabelKey] == OneNetworkLabelValue
}
