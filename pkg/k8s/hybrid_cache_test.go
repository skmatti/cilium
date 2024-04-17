package k8s

import (
	"maps"
	"net"
	"net/netip"
	"reflect"
	"testing"

	"github.com/stretchr/testify/require"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	eventcachetypes "github.com/cilium/cilium/pkg/gke/eventcache/types"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/lock"
)

func TestFindIPv4(t *testing.T) {
	var (
		ipv4Long  = net.IPv4(192, 168, 0, 1)
		ipv4Short = net.IPv4(8, 8, 8, 8).To4()
		ipv6      = net.IP([]byte{0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0x00, 0x00, 0x00, 0x00, 0x8a, 0x2e, 0x03, 0x70, 0x73, 0x34})
	)
	type tc struct {
		ips  [2]net.IP
		want net.IP
	}
	tcs := []tc{
		{
			ips:  [2]net.IP{ipv4Long},
			want: ipv4Long.To4(),
		},
		{
			ips:  [2]net.IP{ipv6, ipv4Short},
			want: ipv4Short,
		},
		{
			ips:  [2]net.IP{ipv6, ipv4Long},
			want: ipv4Long.To4(),
		},
		{
			ips:  [2]net.IP{ipv4Long, ipv4Short},
			want: ipv4Long.To4(),
		},
		{
			ips:  [2]net.IP{ipv6},
			want: nil,
		},
	}
	for _, tc := range tcs {
		got := findIPv4(tc.ips[:])
		require.Equal(t, tc.want, got)
	}
}

type serviceCallParameters struct {
	id  eventcachetypes.ServiceID
	src eventcachetypes.Source
}
type endpointCallParameters struct {
	id     eventcachetypes.ServiceID
	ipPort loadbalancer.L3n4Addr
	src    eventcachetypes.Source
}
type endpointSliceCallParameters struct {
	id    eventcachetypes.ServiceID
	slice EndpointSliceID
	src   eventcachetypes.Source
}

type callCounterForService map[serviceCallParameters]int
type callCounterForEndpoint map[endpointCallParameters]int
type callCounterForEndpointSlice map[endpointSliceCallParameters]int
type mockCache struct {
	serviceUpdateCalls      callCounterForService
	serviceDeleteCalls      callCounterForService
	endpointUpdateCalls     callCounterForEndpoint
	endpointDeleteCalls     callCounterForEndpoint
	manyEndpointUpdateCalls callCounterForEndpointSlice
}

func (c *mockCache) UpdateService(id eventcachetypes.ServiceID, service *Service, src eventcachetypes.Source, swg *lock.StoppableWaitGroup) {
	if c.serviceUpdateCalls == nil {
		c.serviceUpdateCalls = make(callCounterForService)
	}
	c.serviceUpdateCalls[serviceCallParameters{id, src}]++
}
func (c *mockCache) DeleteService(id eventcachetypes.ServiceID, src eventcachetypes.Source, swg *lock.StoppableWaitGroup) {
	if c.serviceDeleteCalls == nil {
		c.serviceDeleteCalls = make(callCounterForService)
	}
	c.serviceDeleteCalls[serviceCallParameters{id, src}]++
}
func (c *mockCache) DeleteEndpoint(id eventcachetypes.ServiceID, ipPort loadbalancer.L3n4Addr, src eventcachetypes.Source, swg *lock.StoppableWaitGroup) {
	if c.endpointDeleteCalls == nil {
		c.endpointDeleteCalls = make(callCounterForEndpoint)
	}
	c.endpointDeleteCalls[endpointCallParameters{id, ipPort, src}]++
}
func (c *mockCache) UpdateEndpoint(id eventcachetypes.ServiceID, ipPort loadbalancer.L3n4Addr, terminating bool, src eventcachetypes.Source, swg *lock.StoppableWaitGroup) {
	if c.endpointUpdateCalls == nil {
		c.endpointUpdateCalls = make(callCounterForEndpoint)
	}
	c.endpointUpdateCalls[endpointCallParameters{id, ipPort, src}]++
}
func (c *mockCache) UpdateManyEndpoints(id eventcachetypes.ServiceID, newEndpoints *Endpoints, src eventcachetypes.Source, swg *lock.StoppableWaitGroup) {
	if c.manyEndpointUpdateCalls == nil {
		c.manyEndpointUpdateCalls = make(callCounterForEndpointSlice)
	}
	c.manyEndpointUpdateCalls[endpointSliceCallParameters{id, newEndpoints.EndpointSliceID, src}]++
}
func TestUpdateOrDeleteServiceInHybrid(t *testing.T) {
	// No t.Parallel() because we overwrite the global variable HybridCache.
	old := HybridCache
	defer func() {
		HybridCache = old
	}()
	svcID := ServiceID{
		Cluster:   "",
		Namespace: "default",
		Name:      "test-service",
	}
	ip := net.ParseIP("127.0.0.1")
	id := eventcachetypes.ServiceID(netip.AddrFrom4([4]byte(ip.To4())))
	svcWithoutLabel := Service{
		FrontendIPs: []net.IP{ip},
		Labels:      map[string]string{"foo": "bar"},
	}
	svcWithLabel := svcWithoutLabel
	svcWithLabel.Labels = maps.Clone(svcWithLabel.Labels)
	svcWithLabel.Labels[OneNetworkLabelKey] = OneNetworkLabelValue

	type testCase struct {
		desc string
		old  *Service
		new  *Service
		want *mockCache
	}
	testCases := []testCase{
		{
			desc: "create service without label",
			old:  nil,
			new:  &svcWithoutLabel,
			want: &mockCache{},
		},
		{
			desc: "add label to service",
			old:  &svcWithoutLabel,
			new:  &svcWithLabel,
			want: &mockCache{
				serviceUpdateCalls: callCounterForService{serviceCallParameters{id, eventcachetypes.KubeAPI}: 1},
			},
		},
		{
			desc: "remove label from service",
			old:  &svcWithLabel,
			new:  &svcWithoutLabel,
			want: &mockCache{
				serviceDeleteCalls: callCounterForService{serviceCallParameters{id, eventcachetypes.KubeAPI}: 1},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			cache := &mockCache{}
			HybridCache = cache
			swg := lock.NewStoppableWaitGroup()
			updateOrDeleteServiceInHybrid(svcID, tc.old, tc.new, swg)
			swg.Stop()
			swg.Wait()
			if !reflect.DeepEqual(cache, tc.want) {
				t.Errorf("Incorrect values in phase %s. Got %+v, want %+v", tc.desc, cache, tc.want)
			}
		})
	}
}

func TestUpdateOrDeleteEndpointsInHybrid(t *testing.T) {
	// No t.Parallel() because we overwrite the global variable HybridCache.
	old := HybridCache
	defer func() {
		HybridCache = old
	}()
	svcID := ServiceID{
		Cluster:   "",
		Namespace: "default",
		Name:      "test-service",
	}
	ip := net.ParseIP("127.0.0.1")
	id := eventcachetypes.ServiceID(netip.AddrFrom4([4]byte(ip.To4())))

	svcWithoutLabel := Service{
		FrontendIPs: []net.IP{ip},
		Labels:      make(map[string]string),
	}
	svcWithLabel := svcWithoutLabel
	svcWithLabel.Labels = maps.Clone(svcWithLabel.Labels)
	svcWithLabel.Labels[OneNetworkLabelKey] = OneNetworkLabelValue
	addr := cmtypes.MustParseAddrCluster("172.20.0.1")
	endpoints := &Endpoints{
		EndpointSliceID: EndpointSliceID{
			ServiceID:         svcID,
			EndpointSliceName: "test-endpointslice",
		},
		Backends: map[cmtypes.AddrCluster]*Backend{
			addr: {
				Ports: map[string]*loadbalancer.L4Addr{
					"foo": {
						Protocol: loadbalancer.NONE,
						Port:     1,
					},
				},
			},
		},
	}
	endpointID := loadbalancer.NewL3n4Addr(loadbalancer.NONE, addr, 1, loadbalancer.ScopeExternal)

	type testCase struct {
		desc      string
		old       *Service
		new       *Service
		endpoints *Endpoints
		want      *mockCache
	}
	testCases := []testCase{
		{
			desc:      "create service without label",
			old:       nil,
			new:       &svcWithoutLabel,
			endpoints: endpoints,
			want:      &mockCache{},
		},
		{
			desc:      "add label to service",
			old:       &svcWithoutLabel,
			new:       &svcWithLabel,
			endpoints: endpoints,
			want: &mockCache{
				manyEndpointUpdateCalls: callCounterForEndpointSlice{endpointSliceCallParameters{id, endpoints.EndpointSliceID, eventcachetypes.KubeAPI}: 1},
			},
		},
		{
			desc:      "remove label from service",
			old:       &svcWithLabel,
			new:       &svcWithoutLabel,
			endpoints: endpoints,
			want: &mockCache{
				endpointDeleteCalls: callCounterForEndpoint{endpointCallParameters{id, *endpointID, eventcachetypes.KubeAPI}: 1},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			cache := &mockCache{}
			HybridCache = cache
			swg := lock.NewStoppableWaitGroup()
			updateOrDeleteEndpointsInHybrid(svcID, tc.old, tc.new, tc.endpoints, swg)
			swg.Stop()
			swg.Wait()
			if !reflect.DeepEqual(cache, tc.want) {
				t.Errorf("Incorrect values in phase %s. Got %+v, want %+v", tc.desc, cache, tc.want)
			}
		})
	}
}
