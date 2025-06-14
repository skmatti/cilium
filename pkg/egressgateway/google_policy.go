package egressgateway

import (
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"time" // Do not use pkg/time in test code.

	networkv1 "github.com/GoogleCloudPlatform/gke-networking-api/apis/network/v1"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/gke/features"
	"github.com/cilium/cilium/pkg/ipcache"
	k8sLbls "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/labels"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maps/egressmap"
	"github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/types"
)

const (
	// NetworkGatewayIPAnnotationKey is the network annotation key used to hold gateway IP.
	NetworkGatewayIPAnnotationKey = "networking.gke.io/gateway-ip"
	TimeoutRegularAnyKey          = "egress.networking.gke.io/TimeoutRegularAnyAnnotation"
	TimeoutRegularTcpKey          = "egress.networking.gke.io/TimeoutRegularTcpAnnotation"
	TimeoutRegularTcpSynKey       = "egress.networking.gke.io/TimeoutRegularTcpSynAnnotation"
	TimeoutRegularTcpFinKey       = "egress.networking.gke.io/TimeoutRegularTcpFinAnnotation"
)

// OnIPIdentityCacheChange is called whenever there is a change of state in the
// IPCache.
func (manager *Manager) OnIPIdentityCacheChange(modType ipcache.CacheModification, cidrCluster cmtypes.PrefixCluster,
	oldHostIP, newHostIP net.IP, oldID *ipcache.Identity, newID ipcache.Identity,
	encryptKey uint8, k8sMeta *ipcache.K8sMetadata) {
	cidr := cidrCluster.AddrCluster().Addr()
	if k8sMeta == nil {
		return
	}
	logger := log.WithFields(logrus.Fields{
		logfields.K8sNamespace: k8sMeta.Namespace,
		logfields.K8sPodName:   k8sMeta.PodName,
		logfields.Identity:     newID.ID.Uint32(),
		logfields.SourceIP:     cidr.String(),
		logfields.ConfigSource: newID.Source,
	})
	epId := endpointID{
		googleEndpointID: googleEndpointID{
			NamespacedName: types.NamespacedName{
				Namespace: k8sMeta.Namespace,
				Name:      k8sMeta.PodName,
			},
			clusterID: newID.ID.ClusterID(),
			ip:        cidr,
		},
	}

	manager.PendingDataStoreUpdate(func() error {
		epData := &endpointMetadata{
			ips: []netip.Addr{cidr},
			id:  epId,
			googleEndpointMetadata: googleEndpointMetadata{
				identityID: newID.ID,
			},
		}
		switch modType {
		case ipcache.Upsert:
			epData.expirationTime = time.Now().Add(manager.pendingIdentityExpiryDuration)
			manager.pendingEPDataStore[epData.id] = epData
			logger.Debug("Endpoint added")
		case ipcache.Delete:
			manager.pendingIPCacheDeleteDataStore[epData.id] = true
			logger.Debug("Endpoint deleted")
		}
		return nil
	})
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
func staticGatewayIP(annotations map[string]string) netip.Addr {
	if annotations == nil {
		return netip.Addr{}
	}
	gatewayIP := annotations[NetworkGatewayIPAnnotationKey]
	ip, err := netip.ParseAddr(gatewayIP)
	if err != nil {
		return netip.Addr{}
	}
	return ip
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

// isMultiNICEndpoint returns true if the endpoint has multi-network label
// and not the default pod-network.
func isMultiNICEndpoint(lblsToMatch k8sLbls.Labels) bool {
	network := lblsToMatch.Get(networkv1.NetworkAnnotationKey)
	return network != "" && !networkv1.IsDefaultNetwork(network)
}

func (manager *Manager) PendingDataStoreUpdate(updateFunc func() error) error {
	manager.googleManager.pendingDataStoreLock.Lock()
	defer manager.googleManager.pendingDataStoreLock.Unlock()
	return updateFunc()
}
