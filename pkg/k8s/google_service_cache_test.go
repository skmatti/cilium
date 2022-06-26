//go:build !privileged_tests
// +build !privileged_tests

/*
Copyright 2022 Google LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

/*
This file contains the logic for ILB services running in GDC-H.  It extends the service cache
logic which is used by both cilium-agent (anetd) and clustermesh-apiserver.
*/

package k8s

import (
	"context"
	"net"
	"reflect"
	"testing"
	"time"

	"github.com/cilium/cilium/pkg/cidr"
	fakeDatapath "github.com/cilium/cilium/pkg/datapath/fake"
	slimv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/service/store"
	serviceStore "github.com/cilium/cilium/pkg/service/store"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

func TestIsIlbService(t *testing.T) {
	testCases := []struct {
		desc string
		svc  *slimv1.Service
		want bool
	}{
		{
			desc: "empty svc",
			want: false,
		},
		{
			desc: "svc with incorrect type",
			svc: &slimv1.Service{ObjectMeta: metav1.ObjectMeta{
				Annotations: map[string]string{serviceAnnotationKey: serviceAnnotationValue}},
				Spec:   slimv1.ServiceSpec{Type: slimv1.ServiceTypeClusterIP},
				Status: slimv1.ServiceStatus{LoadBalancer: slimv1.LoadBalancerStatus{Ingress: []slimv1.LoadBalancerIngress{{IP: "1.2.3.4"}}}},
			},
			want: false,
		},
		{
			desc: "svc with missing annotation",
			svc: &slimv1.Service{ObjectMeta: metav1.ObjectMeta{
				Annotations: map[string]string{serviceAnnotationKey: "foo"}},
				Spec:   slimv1.ServiceSpec{Type: slimv1.ServiceTypeLoadBalancer},
				Status: slimv1.ServiceStatus{LoadBalancer: slimv1.LoadBalancerStatus{Ingress: []slimv1.LoadBalancerIngress{{IP: "1.2.3.4"}}}},
			},
			want: false,
		},
		{
			desc: "VIP is empty",
			svc: &slimv1.Service{ObjectMeta: metav1.ObjectMeta{
				Annotations: map[string]string{serviceAnnotationKey: serviceAnnotationValue}},
				Spec:   slimv1.ServiceSpec{Type: slimv1.ServiceTypeLoadBalancer},
				Status: slimv1.ServiceStatus{LoadBalancer: slimv1.LoadBalancerStatus{Ingress: []slimv1.LoadBalancerIngress{}}},
			},
			want: false,
		},
		{
			desc: "correct svc",
			svc: &slimv1.Service{ObjectMeta: metav1.ObjectMeta{
				Annotations: map[string]string{serviceAnnotationKey: serviceAnnotationValue}},
				Spec:   slimv1.ServiceSpec{Type: slimv1.ServiceTypeLoadBalancer},
				Status: slimv1.ServiceStatus{LoadBalancer: slimv1.LoadBalancerStatus{Ingress: []slimv1.LoadBalancerIngress{{IP: "1.2.3.4"}}}},
			},
			want: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			if got := isIlbService(tc.svc); got != tc.want {
				t.Errorf("isIlbService(%v) = %v, want %v", tc.svc, got, tc.want)
			}
		})
	}
}

func TestIsIlbClusterService(t *testing.T) {
	testCases := []struct {
		desc string
		svc  *store.ClusterService
		want bool
	}{
		{
			desc: "empty svc",
			want: false,
		},
		{
			desc: "svc with no labels",
			svc:  &store.ClusterService{Labels: map[string]string{}},
			want: false,
		},
		{
			desc: "svc with missing type label",
			svc:  &store.ClusterService{Labels: map[string]string{serviceAnnotationKey: serviceAnnotationValue}},
			want: false,
		},
		{
			desc: "svc with missing internal label",
			svc:  &store.ClusterService{Labels: map[string]string{serviceTypeKey: string(slimv1.ServiceTypeLoadBalancer)}},
			want: false,
		},
		{
			desc: "svc with invalid internal type",
			svc:  &store.ClusterService{Labels: map[string]string{serviceTypeKey: string(slimv1.ServiceTypeLoadBalancer), serviceAnnotationKey: "foo"}},
			want: false,
		},
		{
			desc: "svc with invalid type",
			svc:  &store.ClusterService{Labels: map[string]string{serviceTypeKey: string(slimv1.ServiceTypeClusterIP), serviceAnnotationKey: serviceAnnotationValue}},
			want: false,
		},
		{
			desc: "valid ilb svc",
			svc:  &store.ClusterService{Labels: map[string]string{serviceTypeKey: string(slimv1.ServiceTypeLoadBalancer), serviceAnnotationKey: serviceAnnotationValue}},
			want: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			if got := isIlbClusterService(tc.svc); got != tc.want {
				t.Errorf("isIlbService(%v) = %v, want %v", tc.svc, got, tc.want)
			}
		})
	}
}

func TestInjectIlbInfo(t *testing.T) {
	testCases := []struct {
		desc string
		svc  *slimv1.Service
		want map[string]string
	}{
		{
			desc: "inject values",
			svc:  &slimv1.Service{ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{serviceAnnotationKey: serviceAnnotationValue}}, Spec: slimv1.ServiceSpec{Type: slimv1.ServiceTypeLoadBalancer}},
			want: map[string]string{serviceAnnotationKey: serviceAnnotationValue, serviceTypeKey: string(slimv1.ServiceTypeLoadBalancer)},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			service := &Service{}
			injectIlbInfo(tc.svc, service)
			if diff := cmp.Diff(tc.want, service.Labels); diff != "" {
				t.Errorf("got diff for injectIlbInfo(%v, _) %s", tc.svc, diff)
			}
		})
	}
}

func TestIlbConvertService(t *testing.T) {
	testCases := []struct {
		desc string
		// Cluster service being processed
		clusterService *store.ClusterService
		// Endpoints that will exist in the cache for this service
		cacheEndpoints *externalEndpoints
		wantSvc        *Service
	}{
		{
			desc: "Service with one endpoint",
			clusterService: &store.ClusterService{
				Cluster:   "cluster2",
				Name:      "foo",
				Namespace: "default",
				Frontends: map[string]store.PortConfiguration{
					"35.2.3.4": {
						"": &loadbalancer.L4Addr{
							Protocol: loadbalancer.TCP, Port: 80},
					}},
				Backends: map[string]store.PortConfiguration{
					"192.168.1.1": {
						"": &loadbalancer.L4Addr{
							Protocol: loadbalancer.TCP, Port: 9376,
						}}},
				Labels: map[string]string{},
			},
			cacheEndpoints: &externalEndpoints{
				endpoints: map[string]*Endpoints{
					"cluster2": {
						Backends: map[string]*Backend{
							"192.168.1.1": {
								Ports: store.PortConfiguration{
									"": &loadbalancer.L4Addr{
										Protocol: loadbalancer.TCP, Port: 9376,
									}}}}}},
			},
			wantSvc: &Service{
				FrontendIPs:         []net.IP{net.ParseIP("35.2.3.4")},
				TrafficPolicy:       loadbalancer.SVCTrafficPolicyCluster,
				HealthCheckNodePort: 0,
				Ports: map[loadbalancer.FEPortName]*loadbalancer.L4Addr{
					"": {Port: 80, Protocol: loadbalancer.TCP},
				},
				NodePorts:                map[loadbalancer.FEPortName]NodePortToFrontend{},
				Labels:                   map[string]string{},
				Type:                     loadbalancer.SVCTypeClusterIP,
				Selector:                 map[string]string{},
				LoadBalancerSourceRanges: map[string]*cidr.CIDR{},
			},
		},
		{
			desc: "Service with multiple endpoints",
			clusterService: &store.ClusterService{
				Cluster:   "cluster3",
				Name:      "foo",
				Namespace: "default",
				Frontends: map[string]store.PortConfiguration{
					"35.2.3.4": {
						"": &loadbalancer.L4Addr{
							Protocol: loadbalancer.TCP, Port: 8080},
					}},
				Backends: map[string]store.PortConfiguration{
					"192.168.1.1": {
						"": &loadbalancer.L4Addr{
							Protocol: loadbalancer.TCP, Port: 9376,
						}},
					"192.168.1.2": {
						"": &loadbalancer.L4Addr{
							Protocol: loadbalancer.TCP, Port: 9376,
						}},
					"192.168.1.3": {
						"": &loadbalancer.L4Addr{
							Protocol: loadbalancer.TCP, Port: 9376,
						}},
				},
				Labels: map[string]string{},
			},
			cacheEndpoints: &externalEndpoints{
				endpoints: map[string]*Endpoints{
					"cluster3": {
						Backends: map[string]*Backend{
							"192.168.1.1": {
								Ports: store.PortConfiguration{
									"": &loadbalancer.L4Addr{
										Protocol: loadbalancer.TCP, Port: 9376,
									}}},
							"192.168.1.2": {
								Ports: store.PortConfiguration{
									"": &loadbalancer.L4Addr{
										Protocol: loadbalancer.TCP, Port: 9376,
									}}},
							"192.168.1.3": {
								Ports: store.PortConfiguration{
									"": &loadbalancer.L4Addr{
										Protocol: loadbalancer.TCP, Port: 9376,
									}}},
						}}},
			},
			wantSvc: &Service{
				FrontendIPs:         []net.IP{net.ParseIP("35.2.3.4")},
				TrafficPolicy:       loadbalancer.SVCTrafficPolicyCluster,
				HealthCheckNodePort: 0,
				Ports: map[loadbalancer.FEPortName]*loadbalancer.L4Addr{
					"": {Port: 8080, Protocol: loadbalancer.TCP},
				},
				NodePorts:                map[loadbalancer.FEPortName]NodePortToFrontend{},
				Labels:                   map[string]string{},
				Type:                     loadbalancer.SVCTypeClusterIP,
				Selector:                 map[string]string{},
				LoadBalancerSourceRanges: map[string]*cidr.CIDR{},
			},
		},
		{
			desc: "Another cluster with same name/namespace service in endpoints",
			clusterService: &store.ClusterService{
				Cluster:   "cluster3",
				Name:      "foo",
				Namespace: "default",
				Frontends: map[string]store.PortConfiguration{
					"35.2.3.4": {
						"": &loadbalancer.L4Addr{
							Protocol: loadbalancer.TCP, Port: 8080},
					}},
				Backends: map[string]store.PortConfiguration{
					"192.168.1.1": {
						"": &loadbalancer.L4Addr{
							Protocol: loadbalancer.TCP, Port: 9376,
						}},
					"192.168.1.2": {
						"": &loadbalancer.L4Addr{
							Protocol: loadbalancer.TCP, Port: 9376,
						}},
					"192.168.1.3": {
						"": &loadbalancer.L4Addr{
							Protocol: loadbalancer.TCP, Port: 9376,
						}},
				},
				Labels: map[string]string{},
			},
			cacheEndpoints: &externalEndpoints{
				endpoints: map[string]*Endpoints{
					"cluster3": {
						Backends: map[string]*Backend{
							"192.168.1.1": {
								Ports: store.PortConfiguration{
									"": &loadbalancer.L4Addr{
										Protocol: loadbalancer.TCP, Port: 9376,
									}}},
							"192.168.1.2": {
								Ports: store.PortConfiguration{
									"": &loadbalancer.L4Addr{
										Protocol: loadbalancer.TCP, Port: 9376,
									}}},
							"192.168.1.3": {
								Ports: store.PortConfiguration{
									"": &loadbalancer.L4Addr{
										Protocol: loadbalancer.TCP, Port: 9376,
									}}},
						}},
					"cluster4": {
						Backends: map[string]*Backend{
							"192.169.1.1": {
								Ports: store.PortConfiguration{
									"": &loadbalancer.L4Addr{
										Protocol: loadbalancer.TCP, Port: 9376,
									}}},
						}},
				},
			},
			wantSvc: &Service{
				FrontendIPs:         []net.IP{net.ParseIP("35.2.3.4")},
				TrafficPolicy:       loadbalancer.SVCTrafficPolicyCluster,
				HealthCheckNodePort: 0,
				Ports: map[loadbalancer.FEPortName]*loadbalancer.L4Addr{
					"": {Port: 8080, Protocol: loadbalancer.TCP},
				},
				NodePorts:                map[loadbalancer.FEPortName]NodePortToFrontend{},
				Labels:                   map[string]string{},
				Type:                     loadbalancer.SVCTypeClusterIP,
				Selector:                 map[string]string{},
				LoadBalancerSourceRanges: map[string]*cidr.CIDR{},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			cache := NewServiceCache(fakeDatapath.NewNodeAddressing())

			// Seed cache
			id := ServiceID{
				tc.clusterService.Name,
				tc.clusterService.Namespace,
			}
			cache.externalEndpoints[id] = *tc.cacheEndpoints

			// We always want the exact same endpoints that are in the clusterservice object
			wantEndpoints := newEndpoints()
			for ip, port := range tc.clusterService.Backends {
				wantEndpoints.Backends[ip] = &Backend{
					Ports: port,
				}
			}

			svc, endpoints := cache.ilbConvertService(tc.clusterService)
			if diff := cmp.Diff(tc.wantSvc, svc); diff != "" {
				t.Errorf("cache.ilbConvertService(%v) = (%v, _) diff = %s", tc.clusterService, svc, diff)
			}
			if diff := cmp.Diff(wantEndpoints, endpoints); diff != "" {
				t.Errorf("cache.ilbConvertService(%v) = (_, %v) diff = %s", tc.clusterService, endpoints, diff)
			}
		})
	}
}

func TestIlbExternalUpdate(t *testing.T) {
	testCases := []struct {
		desc           string
		clusterService *store.ClusterService
		want           ServiceEvent
	}{
		{
			desc: "Basic update",
			clusterService: &store.ClusterService{
				Cluster:   "cluster2",
				Name:      "foo",
				Namespace: "default",
				Labels: map[string]string{
					serviceTypeKey:       string(slimv1.ServiceTypeLoadBalancer),
					serviceAnnotationKey: serviceAnnotationValue,
				},
			},
			want: ServiceEvent{
				Action: UpdateService,
				ID:     ServiceID{Name: "cluster2-foo", Namespace: "default"},
				Service: NewService(
					nil, nil, nil, nil, false,
					loadbalancer.SVCTrafficPolicyCluster, 0,
					map[string]string{
						serviceTypeKey:       string(slimv1.ServiceTypeLoadBalancer),
						serviceAnnotationKey: serviceAnnotationValue,
					}, map[string]string{}, "default",
					loadbalancer.SVCTypeClusterIP),
				Endpoints: newEndpoints(),
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			cache := NewServiceCache(fakeDatapath.NewNodeAddressing())

			swgSvcs := lock.NewStoppableWaitGroup()
			tc.want.SWG = swgSvcs

			cache.ilbExternalUpdate(tc.clusterService, swgSvcs)

			event := <-cache.Events
			defer event.SWG.Done()

			// Use deepequal since cmp.Diff() cannot handle the SWG
			if !reflect.DeepEqual(tc.want, event) {
				t.Errorf("want %+v, got %+v", tc.want, event)
			}
		})
	}
}

func TestIlbExternalDelete(t *testing.T) {
	testCases := []struct {
		desc           string
		clusterService *store.ClusterService
		want           ServiceEvent
	}{
		{
			desc: "Basic Delete",
			clusterService: &store.ClusterService{
				Cluster:   "cluster2",
				Name:      "foo",
				Namespace: "default",
			},
			want: ServiceEvent{
				Action: DeleteService,
				ID:     ServiceID{Name: "cluster2-foo", Namespace: "default"},
				Service: NewService(
					nil, nil, nil, nil, false,
					loadbalancer.SVCTrafficPolicyCluster, 0,
					nil, map[string]string{}, "default",
					loadbalancer.SVCTypeClusterIP),
				Endpoints: newEndpoints(),
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			cache := NewServiceCache(fakeDatapath.NewNodeAddressing())

			swgSvcs := lock.NewStoppableWaitGroup()
			tc.want.SWG = swgSvcs

			cache.ilbExternalDelete(tc.clusterService, swgSvcs)

			event := <-cache.Events
			defer event.SWG.Done()

			// Use deepequal since cmp.Diff() cannot handle the SWG
			if !reflect.DeepEqual(tc.want, event) {
				t.Errorf("want %v, got %v", tc.want, event)
			}
		})
	}
}

// TestMergeServiceUpdateAndDeleteForILB validates that updating and deleting an
// ILB service generates the correct update and delete events for both the
// remote and local service ID.
//
// Validations are run against MergeCluster and MergeExternal functions.
func TestMergeServiceUpdateAndDeleteForILB(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	cache := NewServiceCache(fakeDatapath.NewNodeAddressing())

	enabledBefore := option.Config.EnableGDCILB
	option.Config.EnableGDCILB = true
	defer func() { option.Config.EnableGDCILB = enabledBefore }()

	swg := lock.NewStoppableWaitGroup()

	localID := ServiceID{Name: "name", Namespace: "ns"}
	remoteID := ServiceID{Name: "other-cluster-name", Namespace: "ns"}
	clusterService := serviceStore.ClusterService{
		Name:      localID.Name,
		Namespace: localID.Namespace,
		Cluster:   "other-cluster",
		Labels: map[string]string{
			serviceAnnotationKey: serviceAnnotationValue,
			serviceTypeKey:       string(slimv1.ServiceTypeLoadBalancer),
		},
		Frontends: map[string]serviceStore.PortConfiguration{"1.1.1.1": {}},
		// Backends provided in test.
	}

	service := &Service{
		FrontendIPs:   []net.IP{net.ParseIP("1.1.1.1")},
		Labels:        clusterService.Labels,
		TrafficPolicy: loadbalancer.SVCTrafficPolicyCluster,
		Type:          loadbalancer.SVCTypeClusterIP,
	}

	opts := cmp.Options{
		cmpopts.EquateEmpty(),
		cmp.AllowUnexported(externalEndpoints{}),
	}

	backendUpdates := []map[string]*Backend{
		{
			"1.1.1.1": {Ports: serviceStore.PortConfiguration{}},
		},
		{
			"1.1.1.1": {Ports: serviceStore.PortConfiguration{}},
			"2.2.2.2": {Ports: serviceStore.PortConfiguration{}},
		},
		{
			"2.2.2.2": {Ports: serviceStore.PortConfiguration{}},
		},
	}

	for i, backendUpdate := range backendUpdates {
		backends := map[string]serviceStore.PortConfiguration{}
		for ip, be := range backendUpdate {
			backends[ip] = be.Ports
		}
		clusterService.Backends = backends
		wantExternalEndpoints := map[ServiceID]externalEndpoints{
			remoteID: {
				endpoints: map[string]*Endpoints{
					clusterService.Cluster: {
						Backends: backendUpdate,
					},
				},
			},
		}
		cache.MergeExternalServiceUpdate(&clusterService, swg)
		if _, ok := cache.services[remoteID]; !ok {
			t.Errorf("After #%d update, cache's services should have ID %s, but did not", i, remoteID)
		}
		if _, ok := cache.services[localID]; ok {
			t.Errorf("After #%d update, cache's services should not have ID %s, but did", i, localID)
		}
		if diff := cmp.Diff(wantExternalEndpoints, cache.externalEndpoints, opts); diff != "" {
			t.Errorf("After #%d update, cache's external endpoints differed (-want +got):\n%s", i+1, diff)
		}

		wantEvent := ServiceEvent{
			Action:    UpdateService,
			ID:        remoteID,
			Service:   service,
			Endpoints: &Endpoints{Backends: backendUpdate},
		}
		select {
		case e := <-cache.Events:
			if diff := cmp.Diff(wantEvent, e, cmpopts.IgnoreFields(ServiceEvent{}, "SWG"), cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("Cache event for remote event differed (-want, +got):\n%s", diff)
			}
		case <-ctx.Done():
			t.Fatalf("Timeout while waiting for remote event")
		}
	}

	cache.MergeExternalServiceDelete(&clusterService, swg)
	if len(cache.services) != 0 {
		t.Errorf("After delete, expected the cache's services to be empty but got %#v", cache.services)
	}
	if len(cache.externalEndpoints) != 0 {
		t.Errorf("After delete, expected the cache's external endpoints to be empty but got %#v", cache.externalEndpoints)
	}

	lastBackends := backendUpdates[len(backendUpdates)-1]
	wantEvent := ServiceEvent{
		Action:    DeleteService,
		ID:        remoteID,
		Service:   service,
		Endpoints: &Endpoints{Backends: lastBackends},
	}
	select {
	case e := <-cache.Events:
		if diff := cmp.Diff(wantEvent, e, cmpopts.IgnoreFields(ServiceEvent{}, "SWG"), opts); diff != "" {
			t.Errorf("Delete event differed (-want, +got):\n%s", diff)
		}
	case <-ctx.Done():
		t.Fatalf("Timeout while waiting for delete event")
	}

	// We should not get any other events.
	ctx, cancel = context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	select {
	case e := <-cache.Events:
		t.Fatalf("Received unexpected event at end of test: %#v", e)
	case <-ctx.Done():
	}
}
