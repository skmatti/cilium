package cmd

import (
	"net"
	"strings"
	"testing"

	"github.com/cilium/cilium/pkg/addressing"
	"github.com/cilium/cilium/pkg/datapath/fake"
	"github.com/cilium/cilium/pkg/endpoint"
	multinicep "github.com/cilium/cilium/pkg/gke/multinic/endpoint"
	"github.com/cilium/cilium/pkg/ipam"
	ipamOption "github.com/cilium/cilium/pkg/ipam/option"
	"github.com/cilium/cilium/pkg/k8s/watchers"
	"github.com/cilium/cilium/pkg/mtu"
	"github.com/cilium/cilium/pkg/nodediscovery"
	"github.com/cilium/cilium/pkg/option"
)

func TestPreAllocateIPsForRestoredMultiNICEndpoints(t *testing.T) {
	option.Config.IPAM = ipamOption.IPAMKubernetes
	d := Daemon{datapath: fake.NewDatapath(), nodeDiscovery: &nodediscovery.NodeDiscovery{}, k8sWatcher: &watchers.K8sWatcher{}, mtuConfig: mtu.Configuration{}}
	d.startIPAM()

	ipv4Addr, _ := addressing.NewCiliumIPv4("10.0.0.1")
	testCases := []struct {
		desc       string
		endpoints  []*endpoint.Endpoint
		multiNIC   bool
		allocators map[string]ipam.Allocator
		wantErr    string
	}{
		{
			desc: "success, no allocation for non-multinic endpoints",
			endpoints: []*endpoint.Endpoint{
				{
					IPv4:       ipv4Addr,
					K8sPodName: "testPod",
				},
			},
		},
		{
			desc: "success, endpoint IP allocated",
			endpoints: []*endpoint.Endpoint{
				{
					IPv4:       ipv4Addr,
					K8sPodName: "testPod",
				},
			},
			multiNIC: true,
			allocators: map[string]ipam.Allocator{
				"test": ipam.NewHostScopeAllocator(&net.IPNet{IP: net.IPv4(10, 0, 0, 0), Mask: net.IPv4Mask(255, 255, 248, 0)}),
			},
		},
		{
			desc: "failure, could not find a right allocator",
			endpoints: []*endpoint.Endpoint{
				{
					IPv4:       ipv4Addr,
					K8sPodName: "testPod",
				},
			},
			multiNIC: true,
			allocators: map[string]ipam.Allocator{
				"test": ipam.NewHostScopeAllocator(&net.IPNet{IP: net.IPv4(30, 0, 0, 0), Mask: net.IPv4Mask(255, 255, 248, 0)}),
			},
			wantErr: "could not find an allocator to allocate the IP 10.0.0.1",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			// setup allocators per test
			d.ipam.MultiNetworkAllocators = tc.allocators
			// set device type for endpoints if multnic
			if tc.multiNIC {
				for _, ep := range tc.endpoints {
					ep.SetDeviceTypeForTest(multinicep.EndpointDeviceMultinicVETH)
				}
			}
			// perform pre-allocation
			err := d.PreAllocateIPsForRestoredMultiNICEndpoints(tc.endpoints)
			if tc.wantErr != "" { // error cases
				if err == nil {
					t.Fatalf("PreAllocateIPsForRestoredMultiNICEndpoints() returns nil but want error %v", tc.wantErr)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("PreAllocateIPsForRestoredMultiNICEndpoints() returns error %v but want error %v", err, tc.wantErr)
				}
			} else {
				if len(d.ipam.MultiNetworkAllocators) == 0 { // non multi-networking cases
					if err != nil {
						t.Fatalf("PreAllocateIPsForRestoredMultiNICEndpoints() returns error %v when there are no allocators but want error nil", err)
					}
				} else {
					allocator, _ := d.ipam.MultiNetworkAllocators["test"]
					allocatedIPs, _ := allocator.Dump()
					for _, ep := range tc.endpoints {
						epIP := ep.GetIPv4Address()
						if _, ok := allocatedIPs[epIP]; !ok {
							t.Fatalf("expected endpoint IP %s to be allocated, but it didn't", epIP)
						}
					}
				}
			}
		})
	}

}
