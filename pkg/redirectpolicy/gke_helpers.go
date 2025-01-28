package redirectpolicy

import (
	"strings"

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

// RemoveExistingNLDBackends removes any backends mapped to the node local DNS LRP.
func (rpm *Manager) RemoveExistingNLDBackends(lrpConfig *LRPConfig) {

	if !rpm.isNodeLocalDNSLRP(lrpConfig) {
		return
	}

	serviceIP := rpm.svcCache.GetServiceFrontendIP(*lrpConfig.serviceID, lb.SVCTypeClusterIP)
	if serviceIP == nil {
		log.Infof("No service IP found for the local redirect service %s", lrpConfig.id.String())
		return
	}
	if len(lrpConfig.frontendMappings) == 0 {
		log.Infof("No LRP frontend mappings found for the local redirect service %s", lrpConfig.id.String())
		return
	}

	// Since the frontend address is same for all the mappings in NLD LRP config, we can only look at the first one to check for backends.
	feMCopy := *lrpConfig.frontendMappings[0]
	if feMCopy.feAddr == nil {

		log.Infof("No frontend found for the local redirect service %s", lrpConfig.id.String())
		return
	}

	feMCopy.feAddr.AddrCluster = cmtypes.MustAddrClusterFromIP(serviceIP)
	if rpm.checkNodeLocalDNSLRP(*feMCopy.feAddr) {
		log.Infof("Removing existing backends for the local redirect service %s", lrpConfig.id.String())
		rpm.notifyPolicyBackendDelete(lrpConfig, &feMCopy)
	}
}

func (rpm *Manager) isNodeLocalDNSLRP(lrpConfig *LRPConfig) bool {
	return lrpConfig.backendSelector.Matches(labels.Set(dnsBackendSelector.LabelSelector.MatchLabels))
}

func (rpm *Manager) checkNodeLocalDNSLRP(frontend lb.L3n4Addr) bool {
	svc, svcFound := rpm.svcManager.GetDeepCopyServiceByFrontend(frontend)
	if !svcFound {
		log.Infof("Node local DNS LRP with frontend %s not found", frontend.String())
		return false
	}

	numBackends := 0
	var beStrings []string
	for _, be := range svc.Backends {
		numBackends++
		beStrings = append(beStrings, be.String())
	}

	log.WithField("frontends", frontend.String()).WithField("backends", strings.Join(beStrings, ",")).Info("Found Node Local DNS LRP")
	if numBackends > 1 {
		log.Warnf("Node local DNS LRP should not have more than 1 backend. Found %d. ", numBackends)
	}
	return true
}
