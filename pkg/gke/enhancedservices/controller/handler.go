package controller

import (
	"fmt"

	ectypes "github.com/cilium/cilium/pkg/gke/eventcache/types"
	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/lock"
	clusterpb "github.com/cilium/proxy/go/envoy/config/cluster/v3"
	corepb "github.com/cilium/proxy/go/envoy/config/core/v3"
	endpointpb "github.com/cilium/proxy/go/envoy/config/endpoint/v3"
	listenerpb "github.com/cilium/proxy/go/envoy/config/listener/v3"
	discoverypb "github.com/cilium/proxy/go/envoy/service/discovery/v3"
	"gke-internal.googlesource.com/kon/pkg/model"
	"gke-internal.googlesource.com/kon/pkg/translate"
	"gke-internal.googlesource.com/kon/pkg/xds"
)

var _ xds.Handler = &handler{}

type handler struct {
	cache k8s.HybridCacheInterface
	swg   *lock.StoppableWaitGroup

	// Watch function for watching xDS resources
	watch func(string, []string) bool
	// Services parsed from the last LDS update.
	// Service IP -> Service.
	// TODO(b/329834401): Use netip.Addr for the IP address once it's parsed in translateLDS.
	services map[string]*model.Service
	// Endpoints parsed from the CDS and EDS updates.
	// CDS name -> endpointSubsetWithID
	endpoints map[string]*endpointSubsetWithID
}

type endpointSubsetWithID struct {
	model.EndpointSubset
	// Used to locate the service ID of the endpoint subset.
	id ectypes.ServiceID
}

func (h *handler) HandleResponse(_ *corepb.Locality, resp *discoverypb.DiscoveryResponse) error {
	typeURL := resp.GetTypeUrl()
	log.Debugf("Handling response with the type of %s", typeURL)
	switch resp.GetTypeUrl() {
	case xds.LDS:
		return h.handleLDS(resp)
	case xds.RDS:
		return h.handleRDS(resp)
	case xds.CDS:
		return h.handleCDS(resp)
	case xds.EDS:
		return h.handleEDS(resp)
	default:
		log.Warningf("Unsupported the xDS type of %s", typeURL)
		return nil
	}
}

func (h *handler) handleLDS(resp *discoverypb.DiscoveryResponse) error {
	parsedServices := make(map[string]*model.Service)
	for _, r := range resp.GetResources() {
		listener := &listenerpb.Listener{}
		if err := r.UnmarshalTo(listener); err != nil {
			return fmt.Errorf("failed to unmarshal resource in LDS response to Listener: %v", err)
		}
		for ip, s := range translate.ParseListner(listener) {
			parsedServices[ip] = s
		}
	}

	for ip := range h.services {
		if _, ok := parsedServices[ip]; !ok {
			// The service IP no longer exist in the latest updates. Remove the service.
			id, err := serviceIDFromIP(ip)
			if err != nil {
				log.Warningf("Failed to parse service IP for %s: %v", ip, err)
				continue
			}
			h.cache.DeleteService(id, ectypes.TDxDS, h.swg)
		}
	}

	var clusters []string
	for ip, s := range parsedServices {
		id, err := serviceIDFromIP(ip)
		if err != nil {
			log.Warningf("Failed to parse service IP for %s: %v", ip, err)
			continue
		}
		for _, p := range s.Ports {
			clusters = append(clusters, p.XDSCluster)
			if _, ok := h.endpoints[p.XDSCluster]; !ok {
				h.endpoints[p.XDSCluster] = &endpointSubsetWithID{}
			}
			h.endpoints[p.XDSCluster].id = id
		}
		svc := k8sService(s)
		h.cache.UpdateService(id, svc, ectypes.TDxDS, h.swg)
	}

	clusterPresence := make(map[string]bool)
	for _, cluster := range clusters {
		clusterPresence[cluster] = true
	}

	for clusterName, eps := range h.endpoints {
		if !clusterPresence[clusterName] {
			for _, endpoint := range eps.Endpoints {
				ipPort, err := l3n4Addr(endpoint.Address)
				if err != nil {
					log.Warningf("Failed to parse endpoint IP %s: %v", endpoint.Address.IP, err)
					continue
				}
				h.cache.DeleteEndpoint(eps.id, *ipPort, ectypes.TDxDS, h.swg)
			}
			delete(h.endpoints, clusterName)
		}
	}

	h.services = parsedServices
	h.watch(xds.CDS, clusters)
	h.watch(xds.EDS, clusters)
	return nil
}

func (h *handler) handleRDS(resp *discoverypb.DiscoveryResponse) error {
	return nil
}

func (h *handler) handleCDS(resp *discoverypb.DiscoveryResponse) error {
	var clusters []*clusterpb.Cluster
	for _, r := range resp.GetResources() {
		cluster := &clusterpb.Cluster{}
		if err := r.UnmarshalTo(cluster); err != nil {
			return fmt.Errorf("failed to unmarshal resource in CDS response to Cluster: %v", err)
		}
		clusters = append(clusters, cluster)
	}

	translate.ParseClusters(h.services, clusters)
	return nil
}

func (h *handler) handleEDS(resp *discoverypb.DiscoveryResponse) error {
	for _, r := range resp.GetResources() {
		cla := &endpointpb.ClusterLoadAssignment{}
		if err := r.UnmarshalTo(cla); err != nil {
			return fmt.Errorf("failed to unmarshal resource in EDS response: %v", err)
		}
		s := translate.ParseCLA(cla)

		existing := h.endpoints[s.XDSCluster]
		if existing == nil {
			log.Warningf("Received EDS for a non-existent CDS %s", s.XDSCluster)
			continue
		}
		upserted, deleted := compareEndpointSubset(&existing.EndpointSubset, s)
		for _, endpoint := range upserted {
			ipPort, err := l3n4Addr(endpoint.Address)
			if err != nil {
				log.Warningf("Failed to parse endpoint IP %s: %v", endpoint.Address.IP, err)
				continue
			}
			h.cache.UpdateEndpoint(existing.id, *ipPort, false, ectypes.TDxDS, h.swg) // TODO(b/350656592): For now, no reliable info regarding endpoint terminating is available.
		}
		for _, endpoint := range deleted {
			ipPort, err := l3n4Addr(endpoint.Address)
			if err != nil {
				log.Warningf("Failed to parse endpoint IP %s: %v", endpoint.Address.IP, err)
				continue
			}
			h.cache.DeleteEndpoint(existing.id, *ipPort, ectypes.TDxDS, h.swg)
		}
		existing.EndpointSubset = *s
	}
	return nil
}
