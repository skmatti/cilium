package k8s

import (
	"context"
	"net/netip"
	"testing"
	"time"

	cmconfig "github.com/cilium/cilium/pkg/clustermesh/config"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/lock"
)

const (
	aliasNameLabel = "service-alias-name"
	gdcProject     = "gdc-project-ns"
)

// newTestService is a helper to create a slim_corev1.Service for testing.
func newTestService(namespace, name string, annotations map[string]string, ports []slim_corev1.ServicePort) *slim_corev1.Service {
	return &slim_corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:   namespace,
			Name:        name,
			Annotations: annotations,
		},
		Spec: slim_corev1.ServiceSpec{
			ClusterIP: "127.0.0.1",
			Type:      slim_corev1.ServiceTypeLoadBalancer,
			Ports:     ports,
		},
		Status: slim_corev1.ServiceStatus{
			LoadBalancer: slim_corev1.LoadBalancerStatus{
				Ingress: []slim_corev1.LoadBalancerIngress{{IP: "1.1.1.1"}},
			},
		},
	}
}

// newTestEndpoints creates a corresponding Endpoints object for a service.
func newTestEndpoints(namespace, name string, subsets []slim_corev1.EndpointSubset) *slim_corev1.Endpoints {
	return &slim_corev1.Endpoints{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Subsets: subsets,
	}
}

func setupAliasingConfig() cmconfig.GoogleConfig {
	googleConfig := cmconfig.GoogleConfig{
		EnableGDCILB:               true,
		EnableServiceAliasing:      true,
		ServiceAliasNamespace:      gdcProject,
		ServiceAliasNameAnnotation: aliasNameLabel,
	}
	return googleConfig
}

func TestServiceAliasing(t *testing.T) {
	googleConfig := setupAliasingConfig()

	defaultPorts := []slim_corev1.ServicePort{
		{Port: 80, Protocol: slim_corev1.ProtocolTCP, Name: "port1"},
		{Port: 81, Protocol: slim_corev1.ProtocolTCP, Name: "port2"},
	}

	defaultSubsets := []slim_corev1.EndpointSubset{
		{
			Addresses: []slim_corev1.EndpointAddress{{IP: "10.0.0.1"}},
			Ports: []slim_corev1.EndpointPort{
				{Name: "port1", Port: 1000, Protocol: slim_corev1.ProtocolTCP},
				{Name: "port2", Port: 2000, Protocol: slim_corev1.ProtocolTCP},
			},
		},
	}

	// Test cases
	tests := []struct {
		name string
		run  func(t *testing.T)
	}{
		{
			name: "Service with alias is created",
			run: func(t *testing.T) {
				cache := NewServiceCache(nil, nil, NewSVCMetricsNoop())
				cache.GoogleConfig = googleConfig
				swg := lock.NewStoppableWaitGroup()
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				defer cancel()

				originalID := ServiceID{Name: "foo", Namespace: "ns1"}
				aliasID := ServiceID{Name: "bar", Namespace: gdcProject}
				svc := newTestService(originalID.Namespace, originalID.Name, map[string]string{aliasNameLabel: aliasID.Name}, defaultPorts)
				endpoints := newTestEndpoints(originalID.Namespace, originalID.Name, defaultSubsets)

				cache.UpdateService(svc, swg)
				cache.UpdateEndpoints(ParseEndpoints(endpoints), swg)

				select {
				case event := <-cache.Events:
					if event.Action != UpdateService || event.ID != aliasID {
						t.Errorf("Expected UpdateService for %v, got %v for %v", aliasID, event.Action, event.ID)
					}
					if _, ok := event.Service.Ports["tcp-80"]; !ok {
						t.Error("Expected service port tcp-80 not found")
					}
					if _, ok := event.Service.Ports["tcp-81"]; !ok {
						t.Error("Expected service port tcp-81 not found")
					}
					ip, err := netip.ParseAddr("10.0.0.1")
					if err != nil {
						t.Fatal(err)
					}
					backend := event.Endpoints.Backends[cmtypes.AddrClusterFrom(ip, 0)]
					if _, ok := backend.Ports["tcp-80"]; !ok {
						t.Error("Expected backend port tcp-80 not found")
					}
					if _, ok := backend.Ports["tcp-81"]; !ok {
						t.Error("Expected backend port tcp-81 not found")
					}
				case <-ctx.Done():
					t.Fatal("Timeout waiting for service update event")
				}
			},
		},
		{
			name: "Service with alias with empty port names",
			run: func(t *testing.T) {
				cache := NewServiceCache(nil, nil, NewSVCMetricsNoop())
				cache.GoogleConfig = googleConfig
				swg := lock.NewStoppableWaitGroup()
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				defer cancel()

				originalID := ServiceID{Name: "empty-port-name", Namespace: "ns1"}
				aliasID := ServiceID{Name: "empty-port-name-alias", Namespace: gdcProject}
				ports := []slim_corev1.ServicePort{{Port: 80, Protocol: slim_corev1.ProtocolTCP, Name: ""}}
				svc := newTestService(originalID.Namespace, originalID.Name, map[string]string{aliasNameLabel: aliasID.Name}, ports)

				subsets := []slim_corev1.EndpointSubset{
					{
						Addresses: []slim_corev1.EndpointAddress{{IP: "10.0.0.1"}},
						Ports:     []slim_corev1.EndpointPort{{Name: "", Port: 1000, Protocol: slim_corev1.ProtocolTCP}},
					},
				}
				endpoints := newTestEndpoints(originalID.Namespace, originalID.Name, subsets)

				cache.UpdateService(svc, swg)
				cache.UpdateEndpoints(ParseEndpoints(endpoints), swg)

				select {
				case event := <-cache.Events:
					if _, ok := event.Service.Ports["tcp-80"]; !ok {
						t.Error("Expected service port tcp-80 not found")
					}
					ip, err := netip.ParseAddr("10.0.0.1")
					if err != nil {
						t.Fatal(err)
					}
					backend := event.Endpoints.Backends[cmtypes.AddrClusterFrom(ip, 0)]
					if _, ok := backend.Ports["tcp-80"]; !ok {
						t.Errorf("Expected backend port 'tcp-80', but it was not found. Ports: %v", backend.Ports)
					}
				case <-ctx.Done():
					t.Fatal("Timeout waiting for service update event")
				}
			},
		},
		{
			name: "Service with alias with non standard port names",
			run: func(t *testing.T) {
				cache := NewServiceCache(nil, nil, NewSVCMetricsNoop())
				cache.GoogleConfig = googleConfig
				swg := lock.NewStoppableWaitGroup()
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				defer cancel()

				originalID := ServiceID{Name: "non-standard-port-name", Namespace: "ns1"}
				aliasID := ServiceID{Name: "non-standard-port-name-alias", Namespace: gdcProject}
				ports := []slim_corev1.ServicePort{{Port: 80, Protocol: slim_corev1.ProtocolTCP, Name: "my-http-port"}}
				svc := newTestService(originalID.Namespace, originalID.Name, map[string]string{aliasNameLabel: aliasID.Name}, ports)

				subsets := []slim_corev1.EndpointSubset{
					{
						Addresses: []slim_corev1.EndpointAddress{{IP: "10.0.0.1"}},
						Ports:     []slim_corev1.EndpointPort{{Name: "my-http-port", Port: 1000, Protocol: slim_corev1.ProtocolTCP}},
					},
				}
				endpoints := newTestEndpoints(originalID.Namespace, originalID.Name, subsets)

				cache.UpdateService(svc, swg)
				cache.UpdateEndpoints(ParseEndpoints(endpoints), swg)

				select {
				case event := <-cache.Events:
					if _, ok := event.Service.Ports["tcp-80"]; !ok {
						t.Error("Expected service port tcp-80 not found")
					}
					ip, err := netip.ParseAddr("10.0.0.1")
					if err != nil {
						t.Fatal(err)
					}
					backend := event.Endpoints.Backends[cmtypes.AddrClusterFrom(ip, 0)]
					if _, ok := backend.Ports["tcp-80"]; !ok {
						t.Errorf("Expected backend port 'tcp-80', but it was not found. Ports: %v", backend.Ports)
					}
				case <-ctx.Done():
					t.Fatal("Timeout waiting for service update event")
				}
			},
		},
		{
			name: "Existing Service alias is modified",
			run: func(t *testing.T) {
				cache := NewServiceCache(nil, nil, NewSVCMetricsNoop())
				cache.GoogleConfig = googleConfig
				swg := lock.NewStoppableWaitGroup()
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()

				originalID := ServiceID{Name: "foo", Namespace: "ns1"}
				oldAliasID := ServiceID{Name: "bar", Namespace: gdcProject}
				newAliasID := ServiceID{Name: "baz", Namespace: gdcProject}
				svc := newTestService(originalID.Namespace, originalID.Name, map[string]string{aliasNameLabel: oldAliasID.Name}, defaultPorts)
				endpoints := newTestEndpoints(originalID.Namespace, originalID.Name, defaultSubsets)

				cache.UpdateService(svc, swg)
				cache.UpdateEndpoints(ParseEndpoints(endpoints), swg)
				<-cache.Events // Discard initial update

				svc.Annotations[aliasNameLabel] = newAliasID.Name
				cache.UpdateService(svc, swg)

				select {
				case event := <-cache.Events:
					if event.Action != DeleteService || event.ID != oldAliasID {
						t.Errorf("Expected DeleteService for %v, got %v for %v", oldAliasID, event.Action, event.ID)
					}
				case <-ctx.Done():
					t.Fatal("Timeout waiting for delete event")
				}

				select {
				case event := <-cache.Events:
					if event.Action != UpdateService || event.ID != newAliasID {
						t.Errorf("Expected UpdateService for %v, got %v for %v", newAliasID, event.Action, event.ID)
					}
					if _, ok := event.Service.Ports["tcp-80"]; !ok {
						t.Error("Expected service port tcp-80 not found")
					}
					if _, ok := event.Service.Ports["tcp-81"]; !ok {
						t.Error("Expected service port tcp-81 not found")
					}
					ip, err := netip.ParseAddr("10.0.0.1")
					if err != nil {
						t.Fatal(err)
					}
					backend := event.Endpoints.Backends[cmtypes.AddrClusterFrom(ip, 0)]
					if _, ok := backend.Ports["tcp-80"]; !ok {
						t.Error("Expected backend port tcp-80 not found")
					}
					if _, ok := backend.Ports["tcp-81"]; !ok {
						t.Error("Expected backend port tcp-81 not found")
					}
				case <-ctx.Done():
					t.Fatal("Timeout waiting for update event")
				}
			},
		},
		{
			name: "Existing Service alias is removed",
			run: func(t *testing.T) {
				cache := NewServiceCache(nil, nil, NewSVCMetricsNoop())
				cache.GoogleConfig = googleConfig
				swg := lock.NewStoppableWaitGroup()
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()

				originalID := ServiceID{Name: "foo", Namespace: "ns1"}
				aliasID := ServiceID{Name: "bar", Namespace: gdcProject}
				svc := newTestService(originalID.Namespace, originalID.Name, map[string]string{aliasNameLabel: aliasID.Name}, defaultPorts)
				endpoints := newTestEndpoints(originalID.Namespace, originalID.Name, defaultSubsets)

				cache.UpdateService(svc, swg)
				cache.UpdateEndpoints(ParseEndpoints(endpoints), swg)
				<-cache.Events // Discard initial update

				delete(svc.Annotations, aliasNameLabel)
				cache.UpdateService(svc, swg)

				select {
				case event := <-cache.Events:
					if event.Action != DeleteService || event.ID != aliasID {
						t.Errorf("Expected DeleteService for %v, got %v for %v", aliasID, event.Action, event.ID)
					}
				case <-ctx.Done():
					t.Fatal("Timeout waiting for delete event")
				}

				select {
				case event := <-cache.Events:
					t.Fatalf("Unexpected event received for service with removed alias: %v", event)
				case <-ctx.Done():
					// Expected
				}
			},
		},
		{
			name: "Service without alias is created",
			run: func(t *testing.T) {
				cache := NewServiceCache(nil, nil, NewSVCMetricsNoop())
				cache.GoogleConfig = googleConfig
				swg := lock.NewStoppableWaitGroup()
				ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
				defer cancel()

				originalID := ServiceID{Name: "foo", Namespace: "ns1"}
				svc := newTestService(originalID.Namespace, originalID.Name, nil, defaultPorts)
				endpoints := newTestEndpoints(originalID.Namespace, originalID.Name, defaultSubsets)

				cache.UpdateService(svc, swg)
				cache.UpdateEndpoints(ParseEndpoints(endpoints), swg)

				select {
				case event := <-cache.Events:
					t.Fatalf("Unexpected event received for service without alias: %v", event)
				case <-ctx.Done():
					// Expected
				}
			},
		},
		{
			name: "Service with multiple ports",
			run: func(t *testing.T) {
				cache := NewServiceCache(nil, nil, NewSVCMetricsNoop())
				cache.GoogleConfig = googleConfig
				swg := lock.NewStoppableWaitGroup()
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				defer cancel()

				originalID := ServiceID{Name: "multi-port", Namespace: "ns1"}
				aliasID := ServiceID{Name: "multi-port-alias", Namespace: gdcProject}
				svc := newTestService(originalID.Namespace, originalID.Name, map[string]string{aliasNameLabel: aliasID.Name}, defaultPorts)
				endpoints := newTestEndpoints(originalID.Namespace, originalID.Name, defaultSubsets)

				cache.UpdateService(svc, swg)
				cache.UpdateEndpoints(ParseEndpoints(endpoints), swg)

				select {
				case event := <-cache.Events:
					if _, ok := event.Service.Ports["tcp-80"]; !ok {
						t.Error("Expected service port tcp-80 not found")
					}
					if _, ok := event.Service.Ports["tcp-81"]; !ok {
						t.Error("Expected service port tcp-81 not found")
					}
					ip, err := netip.ParseAddr("10.0.0.1")
					if err != nil {
						t.Fatal(err)
					}
					backend := event.Endpoints.Backends[cmtypes.AddrClusterFrom(ip, 0)]
					if _, ok := backend.Ports["tcp-80"]; !ok {
						t.Error("Expected port tcp-80 not found")
					}
					if _, ok := backend.Ports["tcp-81"]; !ok {
						t.Error("Expected port tcp-81 not found")
					}
				case <-ctx.Done():
					t.Fatal("Timeout waiting for service update event")
				}
			},
		},
		{
			name: "Service with no endpoints",
			run: func(t *testing.T) {
				cache := NewServiceCache(nil, nil, NewSVCMetricsNoop())
				cache.GoogleConfig = googleConfig
				swg := lock.NewStoppableWaitGroup()
				ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
				defer cancel()

				originalID := ServiceID{Name: "no-ep", Namespace: "ns1"}
				aliasID := ServiceID{Name: "no-ep-alias", Namespace: gdcProject}
				svc := newTestService(originalID.Namespace, originalID.Name, map[string]string{aliasNameLabel: aliasID.Name}, defaultPorts)

				cache.UpdateService(svc, swg)

				select {
				case event := <-cache.Events:
					t.Fatalf("Unexpected event for service with no endpoints: %v", event)
				case <-ctx.Done():
					// Expected
				}
			},
		},
		{
			name: "Endpoints created before service",
			run: func(t *testing.T) {
				cache := NewServiceCache(nil, nil, NewSVCMetricsNoop())
				cache.GoogleConfig = googleConfig
				swg := lock.NewStoppableWaitGroup()
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				defer cancel()

				originalID := ServiceID{Name: "ep-first", Namespace: "ns1"}
				aliasID := ServiceID{Name: "ep-first-alias", Namespace: gdcProject}
				svc := newTestService(originalID.Namespace, originalID.Name, map[string]string{aliasNameLabel: aliasID.Name}, defaultPorts)
				endpoints := newTestEndpoints(originalID.Namespace, originalID.Name, defaultSubsets)

				cache.UpdateEndpoints(ParseEndpoints(endpoints), swg)
				time.Sleep(100 * time.Millisecond) // give time for endpoint to be processed
				cache.UpdateService(svc, swg)

				select {
				case event := <-cache.Events:
					if event.Action != UpdateService || event.ID != aliasID {
						t.Errorf("Expected UpdateService for %v, got %v for %v", aliasID, event.Action, event.ID)
					}
					if _, ok := event.Service.Ports["tcp-80"]; !ok {
						t.Error("Expected service port tcp-80 not found")
					}
					if _, ok := event.Service.Ports["tcp-81"]; !ok {
						t.Error("Expected service port tcp-81 not found")
					}
					ip, err := netip.ParseAddr("10.0.0.1")
					if err != nil {
						t.Fatal(err)
					}
					backend := event.Endpoints.Backends[cmtypes.AddrClusterFrom(ip, 0)]
					if _, ok := backend.Ports["tcp-80"]; !ok {
						t.Error("Expected backend port tcp-80 not found")
					}
					if _, ok := backend.Ports["tcp-81"]; !ok {
						t.Error("Expected backend port tcp-81 not found")
					}
				case <-ctx.Done():
					t.Fatal("Timeout waiting for service update event")
				}
			},
		},
		{
			name: "Invalid alias annotation",
			run: func(t *testing.T) {
				cache := NewServiceCache(nil, nil, NewSVCMetricsNoop())
				cache.GoogleConfig = googleConfig
				swg := lock.NewStoppableWaitGroup()
				ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
				defer cancel()

				originalID := ServiceID{Name: "invalid-alias", Namespace: "ns1"}
				svc := newTestService(originalID.Namespace, originalID.Name, map[string]string{aliasNameLabel: ""}, defaultPorts)
				endpoints := newTestEndpoints(originalID.Namespace, originalID.Name, defaultSubsets)

				cache.UpdateService(svc, swg)
				cache.UpdateEndpoints(ParseEndpoints(endpoints), swg)

				select {
				case event := <-cache.Events:
					t.Fatalf("Unexpected event for service with invalid alias: %v", event)
				case <-ctx.Done():
					// Expected
				}
			},
		},
		{
			name: "Service update without alias change",
			run: func(t *testing.T) {
				cache := NewServiceCache(nil, nil, NewSVCMetricsNoop())
				cache.GoogleConfig = googleConfig
				swg := lock.NewStoppableWaitGroup()
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				defer cancel()

				originalID := ServiceID{Name: "no-alias-change", Namespace: "ns1"}
				aliasID := ServiceID{Name: "no-alias-change-alias", Namespace: gdcProject}
				svc := newTestService(originalID.Namespace, originalID.Name, map[string]string{aliasNameLabel: aliasID.Name}, defaultPorts)
				endpoints := newTestEndpoints(originalID.Namespace, originalID.Name, defaultSubsets)

				cache.UpdateService(svc, swg)
				cache.UpdateEndpoints(ParseEndpoints(endpoints), swg)
				<-cache.Events // consume initial update

				// Update service without changing alias
				svc.Annotations["some-other-annotation"] = "some-value"
				cache.UpdateService(svc, swg)

				select {
				case event := <-cache.Events:
					// Since service spec hasnt changed, normally we should not recieve an event here
					// But with service aliasing service ports can be rewritten
					// after oldService, newService comparison, resulting in an extra event
					if event.Action != UpdateService || event.ID != aliasID {
						t.Errorf("Expected UpdateService for %v, got %v for %v", aliasID, event.Action, event.ID)
					}
					if _, ok := event.Service.Ports["tcp-80"]; !ok {
						t.Error("Expected service port tcp-80 not found")
					}
					if _, ok := event.Service.Ports["tcp-81"]; !ok {
						t.Error("Expected service port tcp-81 not found")
					}
					ip, err := netip.ParseAddr("10.0.0.1")
					if err != nil {
						t.Fatal(err)
					}
					backend := event.Endpoints.Backends[cmtypes.AddrClusterFrom(ip, 0)]
					if _, ok := backend.Ports["tcp-80"]; !ok {
						t.Error("Expected backend port tcp-80 not found")
					}
					if _, ok := backend.Ports["tcp-81"]; !ok {
						t.Error("Expected backend port tcp-81 not found")
					}
				case <-ctx.Done():
					t.Fatalf("Expected event not received.")
				}
			},
		},
		{
			name: "Aliased ILB service deletion",
			run: func(t *testing.T) {
				cache := NewServiceCache(nil, nil, NewSVCMetricsNoop())
				cache.GoogleConfig = googleConfig
				swg := lock.NewStoppableWaitGroup()
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				defer cancel()

				originalID := ServiceID{Name: "foo", Namespace: "ns1"}
				aliasID := ServiceID{Name: "bar", Namespace: gdcProject}

				// Create service with alias annotation AND ILB annotation
				annotations := map[string]string{
					aliasNameLabel:       aliasID.Name,
					serviceAnnotationKey: serviceAnnotationValue,
				}
				svc := newTestService(originalID.Namespace, originalID.Name, annotations, defaultPorts)

				// Add endpoints to satisfy correlateEndpoints
				endpoints := newTestEndpoints(originalID.Namespace, originalID.Name, defaultSubsets)
				cache.UpdateEndpoints(ParseEndpoints(endpoints), swg)

				// 1. Update service - should be aliased
				cache.UpdateService(svc, swg)

				// Verify it's aliased in the UpdateService event
				select {
				case event := <-cache.Events:
					if event.Action != UpdateService || event.ID != aliasID {
						t.Errorf("Expected UpdateService for %v, got %v for %v", aliasID, event.Action, event.ID)
					}
					event.SWG.Done()
				case <-ctx.Done():
					t.Fatal("Timeout waiting for UpdateService event")
				}

				// 2. Delete service - should also be aliased
				cache.DeleteService(svc, swg)

				select {
				case event := <-cache.Events:
					if event.Action != DeleteService || event.ID != aliasID {
						t.Errorf("Expected DeleteService for %v, got %v for %v", aliasID, event.Action, event.ID)
					}
					event.SWG.Done()
				case <-ctx.Done():
					t.Fatal("Timeout waiting for DeleteService event")
				}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, tc.run)
	}
}
