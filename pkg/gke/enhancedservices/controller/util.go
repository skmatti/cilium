package controller

import (
	"fmt"
	"net/netip"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	ectypes "github.com/cilium/cilium/pkg/gke/eventcache/types"
	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"gke-internal.googlesource.com/kon/pkg/model"
)

func serviceIDFromIP(ip string) (ectypes.ServiceID, error) {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return ectypes.ServiceID(addr), fmt.Errorf("failed to parse IP %s: %v", ip, err)
	}
	return ectypes.ServiceID(addr), nil
}

func k8sService(s *model.Service) *k8s.Service {
	svc := &k8s.Service{}
	svc.Ports = make(map[loadbalancer.FEPortName]*loadbalancer.L4Addr)
	for _, p := range s.Ports {
		// p.Name is not populated, so we use p.XDSCluster instead to have a unique key.
		svc.Ports[loadbalancer.FEPortName(p.XDSCluster)] = &loadbalancer.L4Addr{
			// TODO(b/323197949): Populate the protocol once it's present in CDS.
			Protocol: loadbalancer.TCP,
			Port:     uint16(p.Port),
		}
	}
	return svc
}

func l3n4Addr(addr model.Address) (*loadbalancer.L3n4Addr, error) {
	a := &loadbalancer.L3n4Addr{}
	addrCluster, err := cmtypes.ParseAddrCluster(addr.IP)
	if err != nil {
		return nil, fmt.Errorf("failed to parse IP %s: %v", addr.IP, err)
	}
	a.AddrCluster = addrCluster
	a.Port = uint16(addr.Port)
	// TODO(b/323197949): Populate the protocol once it's present in CDS.
	a.Protocol = loadbalancer.TCP
	return a, nil
}

func compareEndpointSubset(old, new *model.EndpointSubset) (upserted []model.Endpoint, deleted []model.Endpoint) {
	oldAddrs, newAddrs := make(map[model.Address]model.Endpoint), make(map[model.Address]model.Endpoint)
	if old != nil {
		for _, e := range old.Endpoints {
			oldAddrs[e.Address] = e
		}
	}
	if new != nil {
		for _, e := range new.Endpoints {
			newAddrs[e.Address] = e
		}
	}

	for addr, old := range oldAddrs {
		if _, ok := newAddrs[addr]; !ok {
			deleted = append(deleted, old)
		}
	}

	for addr, new := range newAddrs {
		if old, ok := oldAddrs[addr]; !ok || old != new {
			upserted = append(upserted, new)
		}
	}
	return
}
