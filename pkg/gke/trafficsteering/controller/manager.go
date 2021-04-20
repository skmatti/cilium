package controller

import (
	"fmt"
	"net/netip"

	"github.com/cilium/cilium/pkg/gke/apis/trafficsteering/v1alpha1"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"k8s.io/apimachinery/pkg/types"
)

type EgressMapInterface interface {
	Update(sourceIP netip.Addr, destCIDR netip.Prefix, egressIP, gatewayIP netip.Addr) error
	Delete(sourceIP netip.Addr, destCIDR netip.Prefix) error
}

// manager manages egress gateway ebpf map.
// All APIs must be called in serial.
type manager struct {
	tsConfigs map[types.NamespacedName]*tsConfig
	podIPs    map[netip.Addr]struct{}
	egressMap EgressMapInterface
}

func newManager(egressMap EgressMapInterface) *manager {
	return &manager{
		tsConfigs: make(map[types.NamespacedName]*tsConfig),
		podIPs:    make(map[netip.Addr]struct{}),
		egressMap: egressMap,
	}
}

// tsConfig holds information parsed from a TrafficSteering CR.
type tsConfig struct {
	name     types.NamespacedName
	dstCIDRs map[netip.Prefix]struct{}
	nextHop  netip.Addr
}

func parse(ts *v1alpha1.TrafficSteering) (*tsConfig, error) {
	cfg := &tsConfig{
		name: types.NamespacedName{
			Namespace: ts.Namespace,
			Name:      ts.Name,
		},
		dstCIDRs: make(map[netip.Prefix]struct{}),
	}
	if len(ts.Spec.Selector.DestinationCIDRs) == 0 {
		return nil, fmt.Errorf("TrafficSteering requires DestinationCIDRs in the selector.")
	}
	for _, dstCIDR := range ts.Spec.Selector.DestinationCIDRs {
		prefix, err := netip.ParsePrefix(dstCIDR)
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR %q: %v", dstCIDR, err)
		}
		if !prefix.Addr().Is4() {
			return nil, fmt.Errorf("doesn't support non-ipv4 address: %s", dstCIDR)
		}
		if _, ok := cfg.dstCIDRs[prefix]; ok {
			return nil, fmt.Errorf("duplicated CIDR: %s", dstCIDR)
		}
		cfg.dstCIDRs[prefix] = struct{}{}
	}
	nextHop, err := netip.ParseAddr(ts.Spec.NextHopIP)
	if err != nil {
		return nil, fmt.Errorf("invalid nextHopIP %q: %v", ts.Spec.NextHopIP, err)
	}
	if !nextHop.Is4() {
		return nil, fmt.Errorf("doesn't support non-ipv4 address: %s", ts.Spec.NextHopIP)
	}
	cfg.nextHop = nextHop
	return cfg, nil
}

func (m *manager) addTSConfig(cfg *tsConfig) error {
	if _, ok := m.tsConfigs[cfg.name]; ok {
		return nil
	}

	for dst := range cfg.dstCIDRs {
		for _, existing := range m.tsConfigs {
			if _, ok := existing.dstCIDRs[dst]; ok {
				return fmt.Errorf("destinationCIDR conflicts with existing ones: %s", dst)
			}
		}
	}
	for pip := range m.podIPs {
		for dst := range cfg.dstCIDRs {
			if err := m.updateEgressMap(pip, dst, cfg.nextHop); err != nil {
				return fmt.Errorf("failed to update egressmap: %v", err)
			}
		}
	}

	m.tsConfigs[cfg.name] = cfg
	return nil
}

func (m *manager) delTSConfig(name types.NamespacedName) error {
	stored, ok := m.tsConfigs[name]
	if !ok {
		return nil
	}

	someFailed := false
	for pip := range m.podIPs {
		for dst := range stored.dstCIDRs {
			if err := m.egressMap.Delete(pip, dst); err != nil {
				log.Warnf("failed to delete entry (%s %s) from egress map: %v", pip, dst, err)
				someFailed = true
			}
		}
	}
	delete(m.tsConfigs, name)
	if someFailed {
		return fmt.Errorf("some EBPF map entries failed to be cleaned up on node %s", nodeTypes.GetName())
	}
	return nil
}

func (m *manager) addPodIP(ip netip.Addr) error {
	if _, ok := m.podIPs[ip]; ok {
		return nil
	}
	for _, cfg := range m.tsConfigs {
		for dst := range cfg.dstCIDRs {
			if err := m.updateEgressMap(ip, dst, cfg.nextHop); err != nil {
				return fmt.Errorf("failed to update egress map: %v", err)
			}
		}
	}

	m.podIPs[ip] = struct{}{}
	return nil
}

func (m *manager) delPodIP(ip netip.Addr) {
	if _, ok := m.podIPs[ip]; !ok {
		return
	}

	for _, cfg := range m.tsConfigs {
		for dst := range cfg.dstCIDRs {
			if err := m.egressMap.Delete(ip, dst); err != nil {
				log.Warnf("failed to delete entry (%s %s) from egress map: %v", ip, dst, err)
			}
		}
	}

	delete(m.podIPs, ip)
}

func (m *manager) updateEgressMap(src netip.Addr, dst netip.Prefix, nextHop netip.Addr) error {
	if err := m.egressMap.Update(src, dst, netip.AddrFrom4([4]byte{255, 255, 255, 255}), nextHop); err != nil {
		return err
	}
	return nil
}
