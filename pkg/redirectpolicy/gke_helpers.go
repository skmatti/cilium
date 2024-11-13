package redirectpolicy

import (
	"net"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/labels"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	lb "github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/policy/api"

	"k8s.io/apimachinery/pkg/types"
)

type dnsPort struct {
	Name     string
	Protocol string
	Port     uint16
}

const (
	dnsSvcName            = "kube-dns"
	dnsSvcNamespace       = "kube-system"
	KeyNodeLocalDNS       = "k8s-app"
	LabelNodeLocalDNS     = "node-local-dns"
	LabelNodeLocalDNSDPv2 = "node-local-dns-dpv2"
	PortNodeLocalDNS      = uint16(53)
)

var (
	dnsPorts = []dnsPort{
		{
			Name:     "dns-tcp",
			Protocol: lb.TCP,
			Port:     PortNodeLocalDNS,
		},
		{
			Name:     "dns",
			Protocol: lb.UDP,
			Port:     PortNodeLocalDNS,
		},
	}
	dnsBackendSelector = api.EndpointSelector{
		LabelSelector: &slim_metav1.LabelSelector{
			MatchLabels: map[string]string{
				KeyNodeLocalDNS: LabelNodeLocalDNS,
			},
		},
	}
)

// DeletedEndpointMetadata is a struct that contains the metadata of a deleted endpoint.
type DeletedEndpointMetadata struct {
	Name      string
	Namespace string
	Labels    map[string]string
	IP        string
}

func ConstructNodeLocalDNSLRP(name, namespace string, uid types.UID) *LRPConfig {
	id := k8s.ServiceID{
		Name:      name,
		Namespace: namespace,
	}
	k8sSvc := k8s.ServiceID{
		Name:      dnsSvcName,
		Namespace: dnsSvcNamespace,
	}
	frontendType := svcFrontendNamedPorts
	feMappings := make([]*feMapping, len(dnsPorts))
	lrpType := lrpConfigTypeSvc
	bePorts := make([]bePortInfo, len(dnsPorts))
	bePortsMap := make(map[portName]*bePortInfo)
	for i, port := range dnsPorts {
		fe := lb.NewL3n4Addr(port.Protocol, cmtypes.AddrCluster{}, port.Port, lb.ScopeExternal)
		feM := &feMapping{
			feAddr: fe,
			fePort: port.Name,
		}
		feMappings[i] = feM
		beP := bePortInfo{
			l4Addr: lb.L4Addr{
				Protocol: port.Protocol,
				Port:     port.Port,
			},
			name: port.Name,
		}
		bePorts[i] = beP
		if len(port.Name) > 0 {
			bePortsMap[port.Name] = &bePorts[i]
		}
	}
	return &LRPConfig{
		uid:                    uid,
		serviceID:              &k8sSvc,
		id:                     id,
		backendSelector:        dnsBackendSelector,
		frontendMappings:       feMappings,
		backendPorts:           bePorts,
		backendPortsByPortName: bePortsMap,
		lrpType:                lrpType,
		frontendType:           frontendType,
	}
}

func (rpm *Manager) GetLocalPodsForPolicy(config *LRPConfig) ([]string, error) {
	pods, err := rpm.getLocalPodsForPolicy(config)
	if err != nil {
		return nil, err
	}
	ret := []string{}
	for _, p := range pods {
		ret = append(ret, p.ips...)
	}
	return ret, nil
}

func (rpm *Manager) onDeleteQueuedEndpointLocked(ep DeletedEndpointMetadata, dnsPort dnsPort) {
	for _, policyConfig := range rpm.policyConfigs {
		for _, feMapping := range policyConfig.frontendMappings {
			if len(feMapping.podBackends) == 0 {
				continue
			}
			pm := &podMetadata{
				labels: ep.Labels,
			}
			// Select the current polices that the endpoint being deleted is a backend for
			if (feMapping.fePort != dnsPort.Name) || (feMapping.feAddr.Protocol != dnsPort.Protocol) || (feMapping.feAddr.Port != dnsPort.Port) || !policyConfig.backendSelector.Matches(labels.Set(pm.labels)) {
				continue
			}

			ipAddr := cmtypes.MustAddrClusterFromIP(net.ParseIP(ep.IP))

			// If the endpoint IP is in podBackends, OnDeletePod() would handle this.
			foundPodinBackends := false
			for _, be := range feMapping.podBackends {
				if be.AddrCluster.Equal(ipAddr) {
					foundPodinBackends = true
					break
				}
			}
			if foundPodinBackends {
				continue
			}

			// At this stage the view of the podBackends in feMapping diverges between
			// what we have in the policyConfig and what we have in the ebpf service map.
			// The ebpf service map has an entry for the already terminated (queued
			// endpoint delete) pod while the policyConfig does not.
			// To remove the stale backend, we make a copy of the feMapping and add an
			// entry for stale pod backend making feMapping_copy consistent with what
			// we have in the ebpf service map.
			feMapping_copy := *feMapping
			staleBackend := backend{
				L3n4Addr: lb.L3n4Addr{
					AddrCluster: ipAddr,
					L4Addr: lb.L4Addr{
						Protocol: dnsPort.Protocol,
						Port:     dnsPort.Port,
					},
				},
				podID: podID{
					Name:      ep.Name,
					Namespace: ep.Namespace,
				},
			}
			feMapping_copy.podBackends = append(feMapping_copy.podBackends, staleBackend)

			// TODO(pkrishn): Revisit this logic. There might be a better way to reconcile.
			// The upsert call with feMapping_copy moves the stale pod from
			// restoredBackendHashes to backends in the service map.
			rpm.upsertService(policyConfig, &feMapping_copy)
			// The second upsert with feMapping removes
			// the staleBackend from svc.backends.
			rpm.upsertService(policyConfig, feMapping)
		}
	}
}

// OnDeleteQueuedEndpoint handles deletion of stale backends when the pod is deleted and the endpoint deletion is queued.
func (rpm *Manager) OnDeleteQueuedEndpoint(ep DeletedEndpointMetadata) {
	rpm.mutex.Lock()
	defer rpm.mutex.Unlock()

	if len(rpm.policyConfigs) == 0 {
		return
	}

	for _, nldPorts := range dnsPorts {
		rpm.onDeleteQueuedEndpointLocked(ep, nldPorts)
	}
}
