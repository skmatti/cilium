package controller

import (
	"fmt"
	"net"

	"github.com/cilium/cilium/pkg/gke/apis/trafficsteering/v1alpha1"
	"github.com/cilium/cilium/pkg/maps/egressmap"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/ebpf"
	"k8s.io/apimachinery/pkg/types"
)

type egressMapInterface interface {
	Update(key, value interface{}, flags ebpf.MapUpdateFlags) error
	Delete(key interface{}) error
}

// manager manages egress gateway ebpf map.
// All APIs must be called in serial.
type manager struct {
	tsConfigs map[types.NamespacedName]*tsConfig
	podIPs    map[string]net.IP
	egressMap egressMapInterface
}

func newManager() *manager {
	return &manager{
		tsConfigs: make(map[types.NamespacedName]*tsConfig),
		podIPs:    make(map[string]net.IP),
		egressMap: egressmap.EgressPolicyMap.Map,
	}
}

// tsConfig holds information parsed from a TrafficSteering CR.
type tsConfig struct {
	name     types.NamespacedName
	dstCIDRs map[string]*net.IPNet
	nextHop  net.IP
}

func parse(ts *v1alpha1.TrafficSteering) (*tsConfig, error) {
	cfg := &tsConfig{
		name: types.NamespacedName{
			Namespace: ts.Namespace,
			Name:      ts.Name,
		},
		dstCIDRs: make(map[string]*net.IPNet),
	}
	if len(ts.Spec.Selector.DestinationCIDRs) == 0 {
		return nil, fmt.Errorf("TrafficSteering requires DestinationCIDRs in the selector.")
	}
	for _, dstCIDR := range ts.Spec.Selector.DestinationCIDRs {
		_, ipNet, err := net.ParseCIDR(dstCIDR)
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR %q: %v", dstCIDR, err)
		}
		if ipNet.IP.To4() == nil {
			return nil, fmt.Errorf("doesn't support non-ipv4 address: %s", dstCIDR)
		}
		if _, ok := cfg.dstCIDRs[ipNet.String()]; ok {
			return nil, fmt.Errorf("duplicated CIDR: %s", dstCIDR)
		}
		cfg.dstCIDRs[ipNet.String()] = ipNet
	}
	nextHop := net.ParseIP(ts.Spec.NextHopIP)
	if nextHop == nil {
		return nil, fmt.Errorf("invalid nextHopIP %q", ts.Spec.NextHopIP)
	}
	if nextHop.To4() == nil {
		return nil, fmt.Errorf("doesn't support non-ipv4 address: %s", ts.Spec.NextHopIP)
	}
	cfg.nextHop = nextHop.To4()
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
	for _, pip := range m.podIPs {
		for _, dst := range cfg.dstCIDRs {
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
	for _, pip := range m.podIPs {
		for _, dst := range stored.dstCIDRs {
			key := egressmap.NewEgressPolicyKey4(pip, dst.IP, dst.Mask)
			if err := m.egressMap.Delete(key); err != nil {
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

func (m *manager) addPodIP(ip net.IP) error {
	if _, ok := m.podIPs[ip.String()]; ok {
		return nil
	}
	for _, cfg := range m.tsConfigs {
		for _, dst := range cfg.dstCIDRs {
			if err := m.updateEgressMap(ip, dst, cfg.nextHop); err != nil {
				return fmt.Errorf("failed to update egress map: %v", err)
			}
		}
	}

	m.podIPs[ip.String()] = ip
	return nil
}

func (m *manager) delPodIP(ip net.IP) {
	if _, ok := m.podIPs[ip.String()]; !ok {
		return
	}

	for _, cfg := range m.tsConfigs {
		for _, dst := range cfg.dstCIDRs {
			key := egressmap.NewEgressPolicyKey4(ip, dst.IP, dst.Mask)
			if err := m.egressMap.Delete(key); err != nil {
				log.Warnf("failed to delete entry (%s %s) from egress map: %v", ip, dst, err)
			}
		}
	}

	delete(m.podIPs, ip.String())
}

func (m *manager) updateEgressMap(src net.IP, dst *net.IPNet, nextHop net.IP) error {
	key := egressmap.NewEgressPolicyKey4(src, dst.IP, dst.Mask)
	value := egressmap.EgressPolicyVal4{}
	copy(value.GatewayIP[:], nextHop.To4())
	if err := m.egressMap.Update(key, value, 0); err != nil {
		return err
	}
	return nil
}
