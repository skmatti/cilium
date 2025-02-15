package redirectpolicy

import (
	"strings"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/k8s"
	slimcorev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/labels"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	lb "github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/sirupsen/logrus"

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

	// Make sure the we remove backend mappings for policies yet to be added.
	if _, ok := rpm.policyConfigs[lrpConfig.id]; ok {
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
	if svc, svcFound := rpm.svcManager.GetDeepCopyServiceByFrontend(*feMCopy.feAddr); svcFound && svc.Type == lb.SVCTypeLocalRedirect {
		var beStrings []string
		for _, be := range svc.Backends {
			beStrings = append(beStrings, be.String())
		}
		log.WithFields(logrus.Fields{
			logfields.LRPType:      lrpConfig.lrpType,
			logfields.K8sNamespace: lrpConfig.id.Namespace,
			logfields.LRPName:      lrpConfig.id.Name,
			"frontends":            feMCopy.feAddr.String(),
			"backends":             strings.Join(beStrings, ","),
		}).Infof("Found Node Local DNS LRP. Removing existing backends.")
		rpm.notifyPolicyBackendDelete(lrpConfig, &feMCopy)
	}
}

// GetNodeLocalDNSLRPBackends returns true if there a service associated with NLD LRP and number of backends for the service.
func (rpm *Manager) GetNodeLocalDNSLRPBackends(lrpConfig *LRPConfig) (bool, int) {

	scopedLog := log.WithFields(logrus.Fields{
		logfields.LRPType:      lrpConfig.lrpType,
		logfields.K8sNamespace: lrpConfig.id.Namespace,
		logfields.LRPName:      lrpConfig.id.Name,
	})

	if !rpm.isNodeLocalDNSLRP(lrpConfig) {
		scopedLog.Info("Not a Node Local DNS LRP")
		return false, 0
	}

	if len(lrpConfig.frontendMappings) == 0 {
		scopedLog.Warn("No LRP frontend mappings found for the local redirect service")
		return false, 0
	}

	// Since the frontend address is same for all the mappings in NLD LRP config, we can only look at the first one to check for backends.
	frontend := lrpConfig.frontendMappings[0].feAddr
	if frontend == nil {
		scopedLog.Warn("No frontend found for the local redirect service")
		return false, 0
	}

	// Look up frontend/service IP if its not populated in the LRP config. The frontend IP address could be unpopulated as the redirect manager does not handle update events.
	if !frontend.AddrCluster.Addr().IsValid() {
		serviceIP := rpm.svcCache.GetServiceFrontendIP(*lrpConfig.serviceID, lb.SVCTypeClusterIP)
		if serviceIP == nil {
			scopedLog.Infof("No service IP found for the local redirect service %s", lrpConfig.id.String())
			return false, 0
		}
		frontend.AddrCluster = cmtypes.MustAddrClusterFromIP(serviceIP)
	}

	svc, svcFound := rpm.svcManager.GetDeepCopyServiceByFrontend(*frontend)
	if !svcFound {
		scopedLog.WithField("frontends", frontend.String()).Info("Service not found")
		return false, 0
	}
	if svc.Type != lb.SVCTypeLocalRedirect {
		scopedLog.WithField("frontends", frontend.String()).Info("Service not local redirect")
		return false, 0
	}

	numBackends := len(svc.Backends)
	var beStrings []string
	for _, be := range svc.Backends {
		beStrings = append(beStrings, be.String())
	}
	scopedLog.WithFields(logrus.Fields{
		"frontends": frontend.String(),
		"backends":  strings.Join(beStrings, ","),
	}).Info("Found Node Local DNS LRP")

	if numBackends > 1 {
		log.Warnf("Node local DNS LRP should not have more than 1 backend. Found %d. ", numBackends)
	}
	return true, numBackends
}

// GetNodeLocalDNSLRPForPod any Node Local DNS LRP associated with the pod. Returns nil ff there is no associated policy.
func (rpm *Manager) GetNodeLocalDNSLRPForPod(pod *slimcorev1.Pod) *LRPConfig {
	if pod == nil || len(rpm.policyConfigs) == 0 {
		return nil
	}

	// Check if the pod is selected by a NLD LRP.
	for _, config := range rpm.policyConfigs {
		if config.policyConfigSelectsPod(pod) && rpm.isNodeLocalDNSLRP(config) {
			return config
		}
	}

	return nil
}

// isNodeLocalDNSLRP returns true if the LRP is associated with Node Local DNS.
func (rpm *Manager) isNodeLocalDNSLRP(lrpConfig *LRPConfig) bool {
	return lrpConfig.backendSelector.Matches(labels.Set(dnsBackendSelector.LabelSelector.MatchLabels))
}
