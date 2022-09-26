package redirectpolicy

import (
	"net"

	"github.com/cilium/cilium/pkg/k8s"
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
		fe := lb.NewL3n4Addr(port.Protocol, net.IP{}, port.Port, lb.ScopeExternal)
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

func (rpm *Manager) GetLocalPodsForPolicy(config *LRPConfig) []string {
	pods := rpm.getLocalPodsForPolicy(config)
	ret := []string{}
	for _, p := range pods {
		ret = append(ret, p.ips...)
	}
	return ret
}
