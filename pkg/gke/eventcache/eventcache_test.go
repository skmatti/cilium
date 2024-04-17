package eventcache

import (
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/cilium/cilium/pkg/clustermesh/types"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	eventcachetypes "github.com/cilium/cilium/pkg/gke/eventcache/types"
	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestLatencyOnSunnyDay(t *testing.T) {
	cache := New()
	//cache.InitMetrics(metrics.NewRegistry(metrics.RegistryParams{DaemonConfig: &option.DaemonConfig{}}))
	cache.Start()
	defer cache.Stop()
	err := testutil.CollectAndCompare(resourceEventDelay, strings.NewReader(""))
	if err != nil {
		t.Errorf("Metric not as expected, got error %v", err)
	}

	id := eventcachetypes.ServiceID(netip.AddrFrom4([4]byte{1, 2, 3, 4}))
	ipCluster, err := types.ParseAddrCluster("8.9.10.11")
	if err != nil {
		t.Errorf("Error while parsing ip: %v", err)
	}
	ipPort := *loadbalancer.NewL3n4Addr(loadbalancer.TCP, ipCluster, 1234, 0)

	type testCase struct {
		desc     string
		function func(eventcachetypes.Source, *lock.StoppableWaitGroup)
		delay    time.Duration
		want     string
	}

	testCases := []testCase{
		{
			desc: "create service",
			function: func(src eventcachetypes.Source, swg *lock.StoppableWaitGroup) {
				cache.UpdateService(id, &k8s.Service{}, src, swg)
			},
			delay: 750 * time.Millisecond,
			want:  readTestdataFile(t, "AddServiceWithin075"),
		},
		{
			desc: "add port to service",
			function: func(src eventcachetypes.Source, swg *lock.StoppableWaitGroup) {
				cache.UpdateService(id, &k8s.Service{Ports: map[loadbalancer.FEPortName]*loadbalancer.L4Addr{"port-8080": loadbalancer.NewL4Addr("tcp", 8080)}}, src, swg)
			},
			delay: 375 * time.Millisecond,
			want:  readTestdataFile(t, "AddPortWithin0375"),
		},
		{
			desc: "delete port from service",
			function: func(src eventcachetypes.Source, swg *lock.StoppableWaitGroup) {
				cache.UpdateService(id, &k8s.Service{}, src, swg)
			},
			delay: 187 * time.Millisecond,
			want:  readTestdataFile(t, "DeletePortWithin0187"),
		},
		{
			desc: "create endpoint",
			function: func(src eventcachetypes.Source, swg *lock.StoppableWaitGroup) {
				cache.UpdateEndpoint(id, ipPort, false, src, swg)
			},
			delay: 100 * time.Millisecond,
			want:  readTestdataFile(t, "AddEndpointWithin01"),
		},
		{
			desc: "update endpoint to terminating",
			function: func(src eventcachetypes.Source, swg *lock.StoppableWaitGroup) {
				cache.UpdateEndpoint(id, ipPort, true, src, swg)
			},
			delay: 600 * time.Millisecond,
			want:  readTestdataFile(t, "UpdateEndpointWithin06"),
		},
		{
			desc: "delete endpoint",
			function: func(src eventcachetypes.Source, swg *lock.StoppableWaitGroup) {
				cache.DeleteEndpoint(id, ipPort, src, swg)
			},
			delay: 275 * time.Millisecond,
			want:  readTestdataFile(t, "DeleteEndpointWithin0275"),
		},
		{
			desc: "delete service",
			function: func(src eventcachetypes.Source, swg *lock.StoppableWaitGroup) {
				cache.DeleteService(id, src, swg)
			},
			delay: 700 * time.Millisecond,
			want:  readTestdataFile(t, "DeleteServiceWithin07"),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			swg1 := lock.NewStoppableWaitGroup()
			swg2 := lock.NewStoppableWaitGroup()
			tc.function(eventcachetypes.KubeAPI, swg1)
			time.Sleep(tc.delay)
			tc.function(eventcachetypes.TDxDS, swg2)
			waitForStoppableWaitGroups(swg1, swg2)
			err = testutil.CollectAndCompare(resourceEventDelay, strings.NewReader(tc.want))
			if err != nil {
				t.Errorf("Metric not as expected, got error %v", err)
			}
			resourceEventDelay.Reset()
		})
	}
}

func waitForStoppableWaitGroups(swgs ...*lock.StoppableWaitGroup) {
	for _, swg := range swgs {
		swg.Stop()
		swg.Wait()
	}
}

func TestUpdatingManyEndpoints(t *testing.T) {
	// No t.Parallel() because the cache must use github.com/cilium/cilium/pkg/metrics/metrics.MustRegister()
	// which is not compatible with dependency injection.
	cache := New()
	cache.Start()
	defer cache.Stop()
	err := testutil.CollectAndCompare(resourceEventDelay, strings.NewReader(""))
	if err != nil {
		t.Errorf("Metric not as expected, got error %v", err)
	}

	id := eventcachetypes.ServiceID(netip.AddrFrom4([4]byte{1, 2, 3, 4}))
	ipCluster1, err := types.ParseAddrCluster("8.9.10.11")
	if err != nil {
		t.Errorf("Error while parsing ip: %v", err)
	}
	ipCluster2, err := types.ParseAddrCluster("9.10.11.12")
	if err != nil {
		t.Errorf("Error while parsing ip: %v", err)
	}
	var (
		port1 uint16 = 1234
		port2 uint16 = 2345
	)
	k8sServiceID := k8s.ServiceID{
		Name:      "test-service",
		Namespace: "test-namespace",
	}
	ipPort1 := *loadbalancer.NewL3n4Addr(loadbalancer.TCP, ipCluster1, port1, 0)
	ipPort2 := *loadbalancer.NewL3n4Addr(loadbalancer.TCP, ipCluster2, port2, 0)
	slice1 := &k8s.Endpoints{
		EndpointSliceID: k8s.EndpointSliceID{
			ServiceID:         k8sServiceID,
			EndpointSliceName: "test-endpointslice-1",
		},
		Backends: map[cmtypes.AddrCluster]*k8s.Backend{
			ipCluster1: {
				Ports: map[string]*loadbalancer.L4Addr{
					"foo": {
						Protocol: loadbalancer.TCP,
						Port:     port1,
					},
				},
			},
		},
	}
	emptySlice1 := *slice1
	emptySlice1.Backends = nil
	slice2 := &k8s.Endpoints{
		EndpointSliceID: k8s.EndpointSliceID{
			ServiceID:         k8sServiceID,
			EndpointSliceName: "test-endpointslice-2",
		},
		Backends: map[cmtypes.AddrCluster]*k8s.Backend{
			ipCluster1: { // This endpoint belongs to two EndpointSlices which is allowed by https://kubernetes.io/docs/concepts/services-networking/endpoint-slices/#duplicate-endpoints
				Ports: map[string]*loadbalancer.L4Addr{
					"foo": {
						Protocol: loadbalancer.TCP,
						Port:     port1,
					},
				},
			},
			ipCluster2: {
				Ports: map[string]*loadbalancer.L4Addr{
					"foo": {
						Protocol: loadbalancer.TCP,
						Port:     port2,
					},
				},
			},
		},
	}
	emptySlice2 := *slice2
	emptySlice2.Backends = nil

	type testCase struct {
		desc            string
		KubeAPIFunction func(*lock.StoppableWaitGroup)
		TDFunction      func(*lock.StoppableWaitGroup)
		delay           time.Duration
		want            string
	}

	testCases := []testCase{
		{
			desc: "create service",
			KubeAPIFunction: func(swg *lock.StoppableWaitGroup) {
				cache.UpdateService(id, &k8s.Service{}, eventcachetypes.KubeAPI, swg)
			},
			TDFunction: func(swg *lock.StoppableWaitGroup) {
				cache.UpdateService(id, &k8s.Service{}, eventcachetypes.TDxDS, swg)
			},
			delay: 750 * time.Millisecond,
			want:  readTestdataFile(t, "AddServiceWithin075"),
		},
		{
			desc: "create endpoint",
			KubeAPIFunction: func(swg *lock.StoppableWaitGroup) {
				cache.UpdateManyEndpoints(id, slice1, eventcachetypes.KubeAPI, swg)
			},
			TDFunction: func(swg *lock.StoppableWaitGroup) {
				cache.UpdateEndpoint(id, ipPort1, false, eventcachetypes.TDxDS, swg)
			},
			delay: 100 * time.Millisecond,
			want:  readTestdataFile(t, "AddEndpointWithin01"),
		},
		{
			desc: "create another endpoint",
			KubeAPIFunction: func(swg *lock.StoppableWaitGroup) {
				cache.UpdateManyEndpoints(id, slice2, eventcachetypes.KubeAPI, swg)
			},
			TDFunction: func(swg *lock.StoppableWaitGroup) {
				cache.UpdateEndpoint(id, ipPort2, false, eventcachetypes.TDxDS, swg)
			},
			delay: 100 * time.Millisecond,
			want:  readTestdataFile(t, "AddEndpointWithin01"),
		},
		{
			desc: "delete one endpoint (the other is removed from test-endpointslice-2 but stays in test-endpointslice-1)",
			KubeAPIFunction: func(swg *lock.StoppableWaitGroup) {
				cache.UpdateManyEndpoints(id, &emptySlice2, eventcachetypes.KubeAPI, swg)
			},
			TDFunction: func(swg *lock.StoppableWaitGroup) {
				cache.DeleteEndpoint(id, ipPort2, eventcachetypes.TDxDS, swg)
			},
			delay: 275 * time.Millisecond,
			want:  readTestdataFile(t, "DeleteEndpointWithin0275"),
		},
		{
			desc: "delete the other endpoint",
			KubeAPIFunction: func(swg *lock.StoppableWaitGroup) {
				cache.UpdateManyEndpoints(id, &emptySlice1, eventcachetypes.KubeAPI, swg)
			},
			TDFunction: func(swg *lock.StoppableWaitGroup) {
				cache.DeleteEndpoint(id, ipPort1, eventcachetypes.TDxDS, swg)
			},
			delay: 275 * time.Millisecond,
			want:  readTestdataFile(t, "DeleteEndpointWithin0275"),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			swg1 := lock.NewStoppableWaitGroup()
			swg2 := lock.NewStoppableWaitGroup()
			tc.KubeAPIFunction(swg1)
			time.Sleep(tc.delay)
			tc.TDFunction(swg2)
			waitForStoppableWaitGroups(swg1, swg2)
			err = testutil.CollectAndCompare(resourceEventDelay, strings.NewReader(tc.want))
			if err != nil {
				t.Errorf("Metric not as expected, got error %v", err)
			}
			resourceEventDelay.Reset()
		})
	}
}

func TestIgnoringIrrelevantChanges(t *testing.T) {
	cache := New()
	cache.Start()
	defer func() {
		cache.Stop()
	}()
	err := testutil.CollectAndCompare(resourceEventDelay, strings.NewReader(""))
	if err != nil {
		t.Errorf("Metric not as expected, got error %v", err)
	}

	id := eventcachetypes.ServiceID(netip.AddrFrom4([4]byte{1, 2, 3, 4}))
	svcWithNonEmptyLabels := &k8s.Service{Labels: map[string]string{"arbitrary-key": "arbitrary-value"}}

	type testCase struct {
		desc     string
		function func(eventcachetypes.Source, *lock.StoppableWaitGroup)
		delay    time.Duration
		want     string
	}

	testCases := []testCase{
		{
			desc: "create service",
			function: func(src eventcachetypes.Source, swg *lock.StoppableWaitGroup) {
				cache.UpdateService(id, &k8s.Service{}, src, swg)
			},
			delay: 100 * time.Millisecond,
			want:  readTestdataFile(t, "AddServiceWithin01"),
		},
		{
			desc: "modify service labels",
			function: func(src eventcachetypes.Source, swg *lock.StoppableWaitGroup) {
				cache.UpdateService(id, svcWithNonEmptyLabels, src, swg)
			},
			delay: 300 * time.Millisecond,
			want:  readTestdataFile(t, "AddServiceWithin01"),
		},
		{
			desc: "delete service",
			function: func(src eventcachetypes.Source, swg *lock.StoppableWaitGroup) {
				cache.DeleteService(id, src, swg)
			},
			delay: 700 * time.Millisecond,
			want:  readTestdataFile(t, "AddServiceWithin01AndDeleteWithin07"),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			swg1 := lock.NewStoppableWaitGroup()
			swg2 := lock.NewStoppableWaitGroup()
			tc.function(eventcachetypes.KubeAPI, swg1)
			time.Sleep(tc.delay)
			tc.function(eventcachetypes.TDxDS, swg2)
			waitForStoppableWaitGroups(swg1, swg2)
			err = testutil.CollectAndCompare(resourceEventDelay, strings.NewReader(tc.want))
			if err != nil {
				t.Errorf("Metric not as expected, got error %v", err)
			}
		})
	}
}

func TestSkippedAddiditionDueToDeletion(t *testing.T) {
	resourceEventDelay.Reset()
	resourceEventLost.Reset()
	resourceEventSkipped.Reset()
	cache := New()
	cache.Start()
	defer func() {
		cache.Stop()
	}()

	for _, metric := range []prometheus.Collector{resourceEventDelay, resourceEventSkipped} {
		if err := testutil.CollectAndCompare(metric, strings.NewReader("")); err != nil {
			t.Errorf("Metric not as expected, got error %v", err)
		}
	}

	id := eventcachetypes.ServiceID(netip.AddrFrom4([4]byte{1, 2, 3, 4}))
	swg := lock.NewStoppableWaitGroup()

	cache.UpdateService(id, &k8s.Service{}, eventcachetypes.KubeAPI, swg)
	time.Sleep(300 * time.Millisecond)
	cache.DeleteService(id, eventcachetypes.KubeAPI, swg)

	time.Sleep(200 * time.Millisecond)
	cache.UpdateService(id, &k8s.Service{}, eventcachetypes.KubeAPI, swg)
	time.Sleep(100 * time.Millisecond)
	cache.UpdateService(id, &k8s.Service{}, eventcachetypes.TDxDS, swg)

	waitForStoppableWaitGroups(swg)

	if err := testutil.CollectAndCompare(resourceEventSkipped, strings.NewReader(readTestdataFile(t, "SkippedAddService"))); err != nil {
		t.Errorf("Metric not as expected, got error %v", err)
	}
	if err := testutil.CollectAndCompare(resourceEventDelay, strings.NewReader(readTestdataFile(t, "AddServiceWithin01"))); err != nil {
		t.Errorf("Metric not as expected, got error %v", err)
	}
}

func TestSkippedAndLostUpdates(t *testing.T) {
	resourceEventDelay.Reset()
	resourceEventLost.Reset()
	resourceEventSkipped.Reset()
	cache := New()
	cache.Start()
	defer func() {
		cache.Stop()
	}()

	for _, metric := range []prometheus.Collector{resourceEventDelay, resourceEventSkipped} {
		if err := testutil.CollectAndCompare(metric, strings.NewReader("")); err != nil {
			t.Errorf("Metric not as expected, got error %v", err)
		}
	}

	id := eventcachetypes.ServiceID(netip.AddrFrom4([4]byte{1, 2, 3, 4}))
	svc0 := &k8s.Service{}
	svc1 := &k8s.Service{Ports: map[loadbalancer.FEPortName]*loadbalancer.L4Addr{
		"port-8080": loadbalancer.NewL4Addr("tcp", 8080),
	}}
	svc2 := &k8s.Service{Ports: map[loadbalancer.FEPortName]*loadbalancer.L4Addr{
		"port-8080": loadbalancer.NewL4Addr("tcp", 8080),
		"port-80":   loadbalancer.NewL4Addr("tcp", 80),
	}}
	svc3 := &k8s.Service{Ports: map[loadbalancer.FEPortName]*loadbalancer.L4Addr{
		"port-8080": loadbalancer.NewL4Addr("tcp", 8080),
		"port-80":   loadbalancer.NewL4Addr("tcp", 80),
		"port-8000": loadbalancer.NewL4Addr("tcp", 8000),
	}}
	svc4 := &k8s.Service{Ports: map[loadbalancer.FEPortName]*loadbalancer.L4Addr{
		"port-8080": loadbalancer.NewL4Addr("tcp", 8080),
		"port-80":   loadbalancer.NewL4Addr("tcp", 80),
		"port-8000": loadbalancer.NewL4Addr("tcp", 8000),
		"port-udp":  loadbalancer.NewL4Addr("udp", 500),
	}}
	swgKube, swgTD := lock.NewStoppableWaitGroup(), lock.NewStoppableWaitGroup()

	cache.UpdateService(id, svc0, eventcachetypes.KubeAPI, swgKube)
	cache.UpdateService(id, svc1, eventcachetypes.KubeAPI, swgKube)
	cache.UpdateService(id, svc2, eventcachetypes.KubeAPI, swgKube)
	cache.UpdateService(id, svc3, eventcachetypes.KubeAPI, swgKube)

	time.Sleep(100 * time.Millisecond)
	cache.UpdateService(id, svc0, eventcachetypes.TDxDS, swgTD)

	time.Sleep(100 * time.Millisecond)
	cache.UpdateService(id, svc2, eventcachetypes.TDxDS, swgTD)

	waitForStoppableWaitGroups(swgKube, swgTD)
	err := testutil.CollectAndCompare( //cache.metrics.
		resourceEventDelay, strings.NewReader(readTestdataFile(t, "AddServiceWithin01AndUpdateServiceWithTwoPortsWithin02WithoutMatching")))
	if err != nil {
		t.Errorf("Metric not as expected, got error %v", err)
	}
	err = testutil.CollectAndCompare( //cache.metrics.
		resourceEventSkipped, strings.NewReader(readTestdataFile(t, "SkippedTwoUpdateServiceFromKubeAPIOneUpdateServiceFromTD")))
	if err != nil {
		t.Errorf("Metric not as expected, got error %v", err)
	}
	err = testutil.CollectAndCompare(resourceEventLost, strings.NewReader(""))
	if err != nil {
		t.Errorf("Metric not as expected, got error %v", err)
	}

	resourceEventDelay.Reset()
	resourceEventSkipped.Reset()
	swgKube, swgTD = lock.NewStoppableWaitGroup(), lock.NewStoppableWaitGroup()

	cache.UpdateService(id, svc3, eventcachetypes.TDxDS, swgTD)
	time.Sleep(time.Second)
	cache.UpdateService(id, svc4, eventcachetypes.KubeAPI, swgKube)

	waitForStoppableWaitGroups(swgKube, swgTD)
	err = testutil.CollectAndCompare(resourceEventDelay, strings.NewReader(readTestdataFile(t, "UpdateServiceWithin02AddPortWithin02")))
	if err != nil {
		t.Errorf("Metric not as expected, got error %v", err)
	}
	err = testutil.CollectAndCompare(resourceEventSkipped, strings.NewReader(""))
	if err != nil {
		t.Errorf("Metric not as expected, got error %v", err)
	}
	err = testutil.CollectAndCompare(resourceEventLost, strings.NewReader(""))
	if err != nil {
		t.Errorf("Metric not as expected, got error %v", err)
	}
}

func TestTimedoutEvent(t *testing.T) {
	resourceEventDelay.Reset()
	resourceEventLost.Reset()
	resourceEventSkipped.Reset()
	config := hybridCacheConfig{
		reviewPeriod:      100 * time.Millisecond,
		cacheEntryTTL:     cacheEntryTTL,
		matchingPeriod:    3 * time.Second,
		channelBufferSize: channelBufferSize,
	}
	cache := new(&config)
	cache.Start()
	defer func() {
		cache.Stop()
	}()

	for _, metric := range []prometheus.Collector{resourceEventDelay, resourceEventLost} {
		if err := testutil.CollectAndCompare(metric, strings.NewReader("")); err != nil {
			t.Errorf("Metric not as expected, got error %v", err)
		}
	}

	id := eventcachetypes.ServiceID(netip.AddrFrom4([4]byte{1, 2, 3, 4}))
	swg := lock.NewStoppableWaitGroup()
	cache.UpdateService(id, &k8s.Service{}, eventcachetypes.KubeAPI, swg)
	waitForStoppableWaitGroups(swg)
	for _, metric := range []prometheus.Collector{resourceEventDelay, resourceEventLost} {
		if err := testutil.CollectAndCompare(metric, strings.NewReader("")); err != nil {
			t.Errorf("Metric not as expected, got error %v", err)
		}
	}

	time.Sleep(config.matchingPeriod + 2*config.reviewPeriod) // Multiply by 2 to be on the safe side.
	if err := testutil.CollectAndCompare(resourceEventLost, strings.NewReader(readTestdataFile(t, "LostAddServiceFromKubeAPI"))); err != nil {
		t.Errorf("Metric not as expected, got error %v", err)
	}
	if err := testutil.CollectAndCompare(resourceEventDelay, strings.NewReader("")); err != nil {
		t.Errorf("Metric not as expected, got error %v", err)
	}
}

func TestAreServicesFromBothSourcesEqual(t *testing.T) {
	t.Parallel() // This tests a single method without creating and starting HybridCache.
	numberedNames := &k8s.Service{Ports: map[loadbalancer.FEPortName]*loadbalancer.L4Addr{
		"port-8080": loadbalancer.NewL4Addr("tcp", 8080),
		"port-80":   loadbalancer.NewL4Addr("tcp", 80),
	}}
	nonTCPPort := &k8s.Service{Ports: map[loadbalancer.FEPortName]*loadbalancer.L4Addr{
		"port-8080": loadbalancer.NewL4Addr("udp", 8080),
		"port-80":   loadbalancer.NewL4Addr("tcp", 80),
	}}
	letteredNames := &k8s.Service{Ports: map[loadbalancer.FEPortName]*loadbalancer.L4Addr{
		"port-A": loadbalancer.NewL4Addr("tcp", 8080),
		"port-B": loadbalancer.NewL4Addr("tcp", 80),
	}}
	singlePort := &k8s.Service{Ports: map[loadbalancer.FEPortName]*loadbalancer.L4Addr{
		"port-8080": loadbalancer.NewL4Addr("tcp", 8080),
	}}

	type testCase struct {
		desc string
		svc1 *k8s.Service
		svc2 *k8s.Service
		want bool
	}

	testCases := []testCase{
		{
			desc: "identical ports named differently",
			svc1: numberedNames,
			svc2: letteredNames,
			want: true,
		},
		{
			desc: "identical names yet protocol mismatch",
			svc1: numberedNames,
			svc2: nonTCPPort,
			want: false,
		},
		{
			desc: "second port missing",
			svc1: numberedNames,
			svc2: singlePort,
			want: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			if got := areServicesFromBothSourcesEqual(tc.svc1, tc.svc2); got != tc.want {
				t.Errorf("areServicesFromBothSourcesEqual returned %v, want %v", got, tc.want)
			}
		})
	}
}

func readTestdataFile(t *testing.T, metricName string) string {
	t.Helper()
	content, err := os.ReadFile("testdata/" + metricName)
	if err != nil {
		t.Fatalf("Reading testdata failed: os.ReadFile for %s returned %v, want nil", metricName, err)
	}
	return string(content)
}
