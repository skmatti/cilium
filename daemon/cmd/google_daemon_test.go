package cmd

import (
	"context"
	"net"
	"testing"

	"github.com/cilium/cilium/pkg/addressing"
	"github.com/cilium/cilium/pkg/datapath/fake"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/endpointmanager"
	multinicep "github.com/cilium/cilium/pkg/gke/multinic/endpoint"
	"github.com/cilium/cilium/pkg/ipam"
	ipamOption "github.com/cilium/cilium/pkg/ipam/option"
	"github.com/cilium/cilium/pkg/k8s/watchers"
	"github.com/cilium/cilium/pkg/mtu"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/nodediscovery"
	"github.com/cilium/cilium/pkg/option"

	networkv1 "k8s.io/cloud-provider-gcp/crd/apis/network/v1"
)

func TestSetupMultiNetworkingIPAMAllocators(t *testing.T) {
	option.Config.IPAM = ipamOption.IPAMKubernetes
	d := Daemon{
		datapath:        fake.NewDatapath(),
		nodeDiscovery:   &nodediscovery.NodeDiscovery{},
		k8sWatcher:      &watchers.K8sWatcher{},
		mtuConfig:       mtu.Configuration{},
		endpointManager: endpointmanager.NewEndpointManager(&watchers.EndpointSynchronizer{}),
	}
	d.startIPAM()
	ipv4Addr, _ := addressing.NewCiliumIPv4("10.0.0.1")
	testCases := []struct {
		desc           string
		annotations    map[string]string
		endpoints      []*endpoint.Endpoint
		wantAllocators map[string]ipam.Allocator
	}{
		{
			desc: "successfully updates IPAM allocators and pre-allocates restored endpoint IPs",
			annotations: map[string]string{
				networkv1.MultiNetworkAnnotationKey: `[{"name":"my-network", "cidrs":["10.0.0.0/21"],"scope":"host-local"}, {"name":"bar", "cidrs":["20.0.0.0/21"],"scope":"host-local"}]`,
			},
			wantAllocators: map[string]ipam.Allocator{
				"my-network": ipam.NewHostScopeAllocator(&net.IPNet{IP: net.IPv4(10, 0, 0, 0), Mask: net.IPv4Mask(255, 255, 224, 0)}),
			},
			endpoints: []*endpoint.Endpoint{
				{
					IPv4:       ipv4Addr,
					K8sPodName: "testPod",
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			node.SetAnnotations(tc.annotations)
			for _, ep := range tc.endpoints {
				ep.SetDeviceTypeForTest(multinicep.EndpointDeviceMultinicVETH)
			}
			err := d.setupMultiNetworkingIPAMAllocators(context.TODO(), tc.endpoints)
			if err != nil {
				t.Fatalf("error in setting up multinic ipam allocators %v", err)
			}
			// verify if allocators are built for all the networks that are part of multinetworking annotation.
			for nw := range tc.wantAllocators {
				if _, ok := d.ipam.MultiNetworkAllocators[nw]; !ok {
					t.Fatalf("expected ipam allocator for network %s to be present, but missing", nw)
				}
			}
			// verify if endpoint IPs are allocated in one of the available allocators.
			for _, ep := range tc.endpoints {
				allocated := false
				for _, allocator := range d.ipam.MultiNetworkAllocators {
					ips, _ := allocator.Dump()
					if _, ok := ips[ep.GetIPv4Address()]; ok {
						allocated = true
						break
					}
				}
				if !allocated {
					t.Fatalf("endpoint IP %s is expected to be allocated in one of the allocators but was not", ep.GetIPv4Address())
				}
			}
		})
	}
}
