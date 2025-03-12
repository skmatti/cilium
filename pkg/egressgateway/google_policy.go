package egressgateway

import (
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"time" // Do not use pkg/time in test code.

	networkv1 "github.com/GoogleCloudPlatform/gke-networking-api/apis/network/v1"
	k8sLbls "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/labels"

	"github.com/cilium/cilium/pkg/gke/features"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/maps/egressmap"
)

const (
	// NetworkGatewayIPAnnotationKey is the network annotation key used to hold gateway IP.
	NetworkGatewayIPAnnotationKey = "networking.gke.io/gateway-ip"
	TimeoutRegularAnyKey          = "egress.networking.gke.io/TimeoutRegularAnyAnnotation"
	TimeoutRegularTcpKey          = "egress.networking.gke.io/TimeoutRegularTcpAnnotation"
	TimeoutRegularTcpSynKey       = "egress.networking.gke.io/TimeoutRegularTcpSynAnnotation"
	TimeoutRegularTcpFinKey       = "egress.networking.gke.io/TimeoutRegularTcpFinAnnotation"
)

// GoogleManager stores the endpoint/policy data specific to google features.
type googleManager struct {
	pendingDataStoreLock lock.Mutex

	// pendingIPCacheDeleteDataStore stores endpoints which are pending deletion.
	pendingIPCacheDeleteDataStore map[endpointID]bool

	pendingIdentityExpiryDuration time.Duration
}

// OnIPIdentityCacheGC is required to implement IPIdentityMappingListener.
func (manager *Manager) OnIPIdentityCacheGC() {
	// There is no need to have anything to synchronize in this case.
}

// skipEgressNATPolicy returns true if egress NAT policies
// must be disabled for the endpoint associated with
// given labels.
// Returns false if enable-google-multi-nic-egress-nat is set to true.
// Otherwise, returns false only for non multi nic endpoints.
func skipEgressNATPolicy(lblsToMatch k8sLbls.Labels) bool {
	if features.GlobalConfig.EnableGoogleMultiNICEgressNAT {
		return false
	}
	network := lblsToMatch.Get(networkv1.NetworkAnnotationKey)
	return network != "" && !networkv1.IsDefaultNetwork(network)
}

// staticGatewayIP returns the gateway IP configured in policy annotations.
func staticGatewayIP(annotations map[string]string) net.IP {
	if annotations == nil {
		return nil
	}
	gatewayIP, _ := annotations[NetworkGatewayIPAnnotationKey]
	return net.ParseIP(gatewayIP)
}

func parseConnectionTimeouts(annotations map[string]string) (*egressmap.ConnectionTimeouts, error) {
	timeouts := &egressmap.ConnectionTimeouts{}
	anyTimeoutSet := false
	timeoutKeys := map[string]*uint32{
		TimeoutRegularAnyKey:    &timeouts.BpfCtTimeoutRegularAny,
		TimeoutRegularTcpKey:    &timeouts.BpfCtTimeoutRegularTcp,
		TimeoutRegularTcpSynKey: &timeouts.BpfCtTimeoutRegularTcpSyn,
		TimeoutRegularTcpFinKey: &timeouts.BpfCtTimeoutRegularTcpFin,
	}

	for key, target := range timeoutKeys {
		if value, ok := annotations[key]; ok && value != "" {
			temp, err := strconv.ParseUint(value, 10, 32)
			if err != nil {
				return nil, fmt.Errorf("failed to parse value for key %s, value: %s: %w", key, value, err)
			}
			if temp == 0 {
				return nil, fmt.Errorf("egress timeouts annotation must be greater than 0 for key %s, value: %s", key, value)
			}

			*target = uint32(temp)
			anyTimeoutSet = true
		}
	}

	if !anyTimeoutSet {
		return nil, nil
	}

	return timeouts, nil
}

func (config *PolicyConfig) forEachEndpointAndCIDRTimeouts(f func(netip.Addr, netip.Prefix, *egressmap.ConnectionTimeouts)) {

	for _, endpoint := range config.matchedEndpoints {
		for _, endpointIP := range endpoint.ips {
			for _, dstCIDR := range config.dstCIDRs {
				f(endpointIP, dstCIDR, config.connectionTimeouts)
			}
		}
	}
}
