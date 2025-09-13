package egressgateway

import (
	"encoding/json"
	"fmt"
	"hash/fnv"
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

	// Cloud NAT Gateway IPs annotation
	CloudNATGatewaysAnnotationKey = "networking.gke.io/cloud-nat-gateways"

	// Timeout annotations
	TimeoutRegularAnyKey    = "egress.networking.gke.io/TimeoutRegularAnyAnnotation"
	TimeoutRegularTcpKey    = "egress.networking.gke.io/TimeoutRegularTcpAnnotation"
	TimeoutRegularTcpSynKey = "egress.networking.gke.io/TimeoutRegularTcpSynAnnotation"
	TimeoutRegularTcpFinKey = "egress.networking.gke.io/TimeoutRegularTcpFinAnnotation"
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
				hash:       getEndpointHash(&epId.googleEndpointID),
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
func staticGatewayIP(annotations map[string]string) (netip.Addr, error) {
	if annotations == nil {
		return netip.Addr{}, nil
	}

	gatewayIP, ok := annotations[NetworkGatewayIPAnnotationKey]
	if !ok || gatewayIP == "" {
		return netip.Addr{}, nil
	}

	addr, err := netip.ParseAddr(gatewayIP)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("failed to parse static gateway IP %s: %w", gatewayIP, err)
	}
	return addr, nil
}

// Cloud NAT Annotation struct
// For safety we'll use a separate struct to distinguish the types used by the UNET reconciler (net.IP)
type CloudNATGatewayIPsSerialized struct {
	EgressIP  net.IP `json:"egressIP"`
	GatewayIP net.IP `json:"gatewayIP"`
}

type CloudNATGatewayIPs struct {
	EgressIP  netip.Addr
	GatewayIP netip.Addr
}

func EncodeCloudNATGatewayInfos(inputGws []CloudNATGatewayIPs) (string, error) {
	// Need to initialize it if non-nil, even if it's empty, so the stringification works correctly.
	// If not initialized it gets stringified to "null". If initialized bu t empty to "[]"
	var gws []CloudNATGatewayIPsSerialized
	if inputGws != nil {
		gws = make([]CloudNATGatewayIPsSerialized, 0, len(inputGws))
	}

	for _, inputGw := range inputGws {
		gw := CloudNATGatewayIPsSerialized{
			EgressIP:  net.IP(inputGw.EgressIP.AsSlice()),
			GatewayIP: net.IP(inputGw.GatewayIP.AsSlice()),
		}
		gws = append(gws, gw)
	}

	jsonData, err := json.Marshal(gws)
	if err != nil {
		return "", err
	}
	return string(jsonData), nil
}

func DecodeCloudNATGateways(jsonString string) ([]CloudNATGatewayIPs, error) {
	var inputGws []CloudNATGatewayIPsSerialized
	if err := json.Unmarshal([]byte(jsonString), &inputGws); err != nil {
		return nil, err
	}

	getAddr := func(ip net.IP) (netip.Addr, bool) {
		// Check if it's an IPv4 ot IPv6
		ip4 := ip.To4()
		if ip4 != nil {
			ip = ip4
		}
		return netip.AddrFromSlice(ip)
	}

	// Need to initialize it if non-nil, even if it's empty, so the destringifycation works correctly.
	// "null" gets de-stringified to a nil slice, "[]" to an empty slice.
	var gws []CloudNATGatewayIPs
	if inputGws != nil {
		gws = make([]CloudNATGatewayIPs, 0, len(inputGws))
	}

	for _, inputGw := range inputGws {
		egressIP, ok := getAddr(inputGw.EgressIP)
		if !ok {
			return nil, fmt.Errorf("Failed to parse egressIP %s", inputGw.EgressIP)
		}
		gatewayIP, ok := getAddr(inputGw.GatewayIP)
		if !ok {
			return nil, fmt.Errorf("Failed to parse gatewayIP %s", inputGw.GatewayIP)
		}
		gw := CloudNATGatewayIPs{
			EgressIP:  egressIP,
			GatewayIP: gatewayIP,
		}
		gws = append(gws, gw)
	}

	return gws, nil
}

// getCloudNATGatewayIPs returns a nil array and no error if the annotation is not present.
func getCloudNATGatewayIPs(annotations map[string]string) ([]CloudNATGatewayIPs, error) {
	if annotations == nil {
		return nil, nil
	}

	encodedData, ok := annotations[CloudNATGatewaysAnnotationKey]
	if !ok || encodedData == "" {
		return nil, nil
	}

	gws, err := DecodeCloudNATGateways(encodedData)
	if err != nil {
		return nil, err
	}
	return gws, nil
}

// Timeouts
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

// getEndpointHash will generate the endpoint hash based on its name, ns, clusterID, and IP.
func getEndpointHash(epID *googleEndpointID) uint64 {
	// Using "||" since it's a forbidden character on in endpoints names and namespaces.
	return computeEndpointHash(fmt.Sprintf("%s||%s||%s||%d", epID.Name, epID.Namespace, epID.ip, epID.clusterID))
}

// Consistent Hashing & gateway distribution
//
// The func consistentHash32() below is copied from google3/util/hash/go/hash.go, which is the
// same hash function as C++'s GetConsistentHash() from util/hash/consistent_hash.cc, and is
// also compatible with com.google.common.hash.Hashing.consistentHash.
//
// ConsistentHash32 returns a hash value in the range [0,n-1].
//
// The input value h is arbitrary and does not need to be
// well-distributed. The value n must be in the range [1,2^31-2].
// The hash values are evenly distributed across buckets, and satisfy
// the property that if H(h,n) != H(h,n-1), then H(h,n) == n-1.
//
// In this case h is the hash of the endpoint_id and n is the number of gateways.
func consistentHash32(h uint64, n int32) int32 {
	if n <= 0 {
		panic("n must be greater than zero")
	}
	b := int32(0) // The current bucket number, 1 <= b <= n (initially invalid).
	j := int32(1) // The destination of the next jump.

	// Jump from bucket to bucket until the next candidate is too large.
	for j > 0 && j <= n {
		b = j
		h = h*2862933555777941757 + 1
		// The code below implements j = floor(b/r) + 1.
		inv_r := float64(1<<31) / float64(int32(h>>33)+1)
		j = int32(float64(b)*inv_r + 1)
	}
	return b - 1
}

func computeEndpointHash(endpointIdentifier string) uint64 {
	h := fnv.New64()
	h.Write([]byte(endpointIdentifier))
	return h.Sum64()
}

func pickGateway(gateways []gatewayConfig, epHash uint64) *gatewayConfig {
	index := consistentHash32(epHash, int32(len(gateways)))
	return &gateways[index]
}
