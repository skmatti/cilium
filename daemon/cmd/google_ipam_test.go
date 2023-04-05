package cmd

import (
	"net"
	"strings"
	"testing"

	"github.com/cilium/cilium/pkg/cidr"
	"github.com/cilium/cilium/pkg/datapath/fake"
	"github.com/cilium/cilium/pkg/ipam"
	ipamOption "github.com/cilium/cilium/pkg/ipam/option"
	"github.com/cilium/cilium/pkg/k8s/watchers"
	"github.com/cilium/cilium/pkg/mtu"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/nodediscovery"
	"github.com/cilium/cilium/pkg/option"
	"github.com/google/go-cmp/cmp"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	networkv1 "k8s.io/cloud-provider-gcp/crd/apis/network/v1"
)

func TestUpdateMultiNetworkIPAMAllocators(t *testing.T) {
	option.Config.IPAM = ipamOption.IPAMKubernetes
	d := Daemon{datapath: fake.NewDatapath(), nodeDiscovery: &nodediscovery.NodeDiscovery{}, k8sWatcher: &watchers.K8sWatcher{}, mtuConfig: mtu.Configuration{}}
	d.startIPAM()

	testCases := []struct {
		desc                string
		nodeAnnotations     map[string]string
		existingAllocators  map[string]ipam.Allocator
		existingPodNetworks map[string]*cidr.CIDR
		wantAllocators      map[string]ipam.Allocator
		wantPodNetworks     map[string]*cidr.CIDR
		wantError           string
	}{
		{
			desc:            "missing multi network annotation key",
			nodeAnnotations: map[string]string{"name": "node-1"},
		},
		{
			desc:            "invalid multi network annotation key",
			nodeAnnotations: map[string]string{networkv1.MultiNetworkAnnotationKey: `invalid_annotation`},
			wantError:       "invalid format for multi-network annotation",
		},
		{
			desc:            "add new network allocators to existing allocators",
			nodeAnnotations: map[string]string{networkv1.MultiNetworkAnnotationKey: `[{"name":"my-network", "cidrs":["10.0.0.0/21"],"scope":"host-local"}, {"name":"bar", "cidrs":["20.0.0.0/21"],"scope":"host-local"}]`},
			existingAllocators: map[string]ipam.Allocator{
				"my-network": ipam.NewHostScopeAllocator(&net.IPNet{IP: net.IPv4(10, 0, 0, 0), Mask: net.IPv4Mask(255, 255, 224, 0)}),
			},
			wantAllocators: map[string]ipam.Allocator{
				"my-network": ipam.NewHostScopeAllocator(&net.IPNet{IP: net.IPv4(10, 0, 0, 0), Mask: net.IPv4Mask(255, 255, 224, 0)}),
				"bar":        ipam.NewHostScopeAllocator(&net.IPNet{IP: net.IPv4(20, 0, 0, 0), Mask: net.IPv4Mask(255, 255, 224, 0)}),
			},
			wantPodNetworks: map[string]*cidr.CIDR{
				"my-network": cidr.NewCIDR(&net.IPNet{IP: net.IPv4(10, 0, 0, 0), Mask: net.IPv4Mask(255, 255, 224, 0)}),
				"bar":        cidr.NewCIDR(&net.IPNet{IP: net.IPv4(20, 0, 0, 0), Mask: net.IPv4Mask(255, 255, 224, 0)}),
			},
		},
		{
			desc:            "updates to existing allocators",
			nodeAnnotations: map[string]string{networkv1.MultiNetworkAnnotationKey: `[{"name":"bar", "cidrs":["20.0.0.0/21"],"scope":"host-local"}]`},
			existingAllocators: map[string]ipam.Allocator{
				"my-network": ipam.NewHostScopeAllocator(&net.IPNet{IP: net.IPv4(10, 0, 0, 0), Mask: net.IPv4Mask(255, 255, 224, 0)}),
			},
			existingPodNetworks: map[string]*cidr.CIDR{
				"my-network": cidr.NewCIDR(&net.IPNet{IP: net.IPv4(10, 0, 0, 0), Mask: net.IPv4Mask(255, 255, 224, 0)}),
			},
			wantAllocators: map[string]ipam.Allocator{
				"bar": ipam.NewHostScopeAllocator(&net.IPNet{IP: net.IPv4(20, 0, 0, 0), Mask: net.IPv4Mask(255, 255, 224, 0)}),
			},
			wantPodNetworks: map[string]*cidr.CIDR{
				"bar": cidr.NewCIDR(&net.IPNet{IP: net.IPv4(20, 0, 0, 0), Mask: net.IPv4Mask(255, 255, 224, 0)}),
			},
		},
	}

	for _, tc := range testCases {
		// set existing allocators per test case
		d.ipam.MultiNetworkAllocators = tc.existingAllocators
		node.SetPodNetworks(tc.existingPodNetworks)
		err := d.UpdateMultiNetworkIPAMAllocators(tc.nodeAnnotations)
		if tc.wantError != "" {
			if err == nil {
				t.Fatalf("UpdateMultiNetworkIPAMAllocators() returns nil but want error %v", tc.wantError)
			}
			if !strings.HasPrefix(err.Error(), tc.wantError) {
				t.Fatalf("UpdateMultiNetworkIPAMAllocators() returns error %v but want error %v", err, tc.wantError)
			}
		}
		for nw := range tc.wantAllocators {
			if _, ok := d.ipam.MultiNetworkAllocators[nw]; !ok {
				t.Fatalf("expected ipam allocator for network %s to be present, but is absent", nw)
			}
		}
		for nw := range tc.wantPodNetworks {
			if _, ok := node.GetPodNetworks()[nw]; !ok {
				t.Fatalf("expected cidr for network %s to be present, but is absent", nw)
			}
		}
		for nw := range node.GetPodNetworks() {
			if _, ok := tc.wantAllocators[nw]; !ok {
				t.Fatalf("expected cidr for network %s to be absent, but is present", nw)
			}
		}
	}
}

func TestReserveGatewayIP(t *testing.T) {
	option.Config.IPAM = ipamOption.IPAMKubernetes
	d := Daemon{datapath: fake.NewDatapath(), nodeDiscovery: &nodediscovery.NodeDiscovery{}, k8sWatcher: &watchers.K8sWatcher{}, mtuConfig: mtu.Configuration{}}
	d.startIPAM()

	testCases := []struct {
		desc               string
		network            *networkv1.Network
		preAllocatedIPs    map[string]string
		existingAllocators map[string]ipam.Allocator
		podNetworks        map[string]*cidr.CIDR
		wantGatewayIP      string
		wantError          string
	}{
		{
			desc: "success, no gateway IP reservation for default network",
			network: &networkv1.Network{
				ObjectMeta: v1.ObjectMeta{
					Name: networkv1.DefaultPodNetworkName,
				},
			},
			existingAllocators: map[string]ipam.Allocator{
				"test": ipam.NewHostScopeAllocator(&net.IPNet{IP: net.IPv4(20, 0, 0, 0), Mask: net.IPv4Mask(255, 255, 224, 0)}),
			},
		},
		{
			desc: "success, no gateway IP reservation for non-l3 typed network",
			network: &networkv1.Network{
				ObjectMeta: v1.ObjectMeta{
					Name: "test",
				},
				Spec: networkv1.NetworkSpec{
					Type: networkv1.L2NetworkType,
				},
			},
			existingAllocators: map[string]ipam.Allocator{
				"test": ipam.NewHostScopeAllocator(&net.IPNet{IP: net.IPv4(20, 0, 0, 0), Mask: net.IPv4Mask(255, 255, 224, 0)}),
			},
		},
		{
			desc: "success, reserve gateway IP for network",
			network: &networkv1.Network{
				ObjectMeta: v1.ObjectMeta{
					Name: "test",
				},
				Spec: networkv1.NetworkSpec{
					Type: networkv1.L3NetworkType,
				},
			},
			existingAllocators: map[string]ipam.Allocator{
				"test": ipam.NewHostScopeAllocator(&net.IPNet{IP: net.IPv4(20, 0, 0, 0), Mask: net.IPv4Mask(255, 255, 248, 0)}),
			},
			podNetworks: map[string]*cidr.CIDR{
				"test": cidr.MustParseCIDR("20.0.0.0/21"),
			},
			wantGatewayIP: "20.0.0.1",
		},
		{
			desc: "success, gateway IP already reserved for network",
			network: &networkv1.Network{
				ObjectMeta: v1.ObjectMeta{
					Name: "test",
				},
				Spec: networkv1.NetworkSpec{
					Type: networkv1.L3NetworkType,
				},
			},
			preAllocatedIPs: map[string]string{
				"20.0.0.1": "",
			},
			existingAllocators: map[string]ipam.Allocator{
				"test": ipam.NewHostScopeAllocator(&net.IPNet{IP: net.IPv4(20, 0, 0, 0), Mask: net.IPv4Mask(255, 255, 248, 0)}),
			},
			podNetworks: map[string]*cidr.CIDR{
				"test": cidr.MustParseCIDR("20.0.0.0/21"),
			},
			wantGatewayIP: "20.0.0.1",
		},
		{
			desc: "failure, missing allocator to allocate gateway IP",
			network: &networkv1.Network{
				ObjectMeta: v1.ObjectMeta{
					Name: "test",
				},
				Spec: networkv1.NetworkSpec{
					Type: networkv1.L3NetworkType,
				},
			},
			existingAllocators: map[string]ipam.Allocator{
				"nw": ipam.NewHostScopeAllocator(&net.IPNet{IP: net.IPv4(20, 0, 0, 0), Mask: net.IPv4Mask(255, 255, 224, 0)}),
			},
			wantError: "allocator for network test is not present, cannot reserve a gateway IP",
		},
		{
			desc: "failure, missing network cidr to allocate gateway IP",
			network: &networkv1.Network{
				ObjectMeta: v1.ObjectMeta{
					Name: "test",
				},
				Spec: networkv1.NetworkSpec{
					Type: networkv1.L3NetworkType,
				},
			},
			existingAllocators: map[string]ipam.Allocator{
				"test": ipam.NewHostScopeAllocator(&net.IPNet{IP: net.IPv4(20, 0, 0, 0), Mask: net.IPv4Mask(255, 255, 224, 0)}),
			},
			podNetworks: map[string]*cidr.CIDR{},
			wantError:   "missing cidr for network test, cannot reserve a gateway IP",
		},
	}
	for _, tc := range testCases {
		// set existing allocators per test case
		d.ipam.MultiNetworkAllocators = tc.existingAllocators
		node.SetPodNetworks(tc.podNetworks)

		// pre-allocate IPs in allocators
		for _, ip := range tc.preAllocatedIPs {
			allocator := d.ipam.MultiNetworkAllocators[tc.network.Name]
			allocator.Allocate(net.ParseIP(ip), "")
		}

		// attempt reserving gateway IP
		err := d.ReserveGatewayIP(tc.network)

		// verify no other IPs are allocated other than the preAllocatedIPs
		if len(tc.preAllocatedIPs) != 0 {
			allocator, _ := d.ipam.MultiNetworkAllocators[tc.network.Name]
			allocatedIPs, _ := allocator.Dump()
			if diff := cmp.Diff(tc.preAllocatedIPs, allocatedIPs); diff != "" {
				t.Fatalf("ReserveGatewayIP() returns different allocated IPs: (-got +want): %s", diff)
			}
		} else {
			if tc.wantError != "" { // error cases
				if err == nil {
					t.Fatalf("ReserveGatewayIP() returns no error but want error: %v", tc.wantError)
				}
				if !strings.HasPrefix(err.Error(), tc.wantError) {
					t.Fatalf("ReserveGatewayIP() returns error %v but want error: %v", err, tc.wantError)
				}
			} else {
				if networkv1.IsDefaultNetwork(tc.network.Name) { // default network check
					if err != nil {
						t.Fatalf("ReserveGatewayIP() returns error %v for default network expected no error", err)
					}
				} else { // non-default networks
					allocator, _ := d.ipam.MultiNetworkAllocators[tc.network.Name]
					allocatedIPs, _ := allocator.Dump()
					if tc.wantGatewayIP == "" { // verify no IPs are allocated if test case's expected gatewayIP is empty.
						if len(allocatedIPs) != 0 {
							t.Fatalf("expected allocator's ip dump to be empty for network %s but allocated IPs: %v", tc.network.Name, allocatedIPs)
						}
					} else {
						if _, ok := allocatedIPs[tc.wantGatewayIP]; !ok {
							t.Fatalf("expected gatewayIP %s to be allocated, but it didn't", tc.wantGatewayIP)
						}
					}
				}
			}
		}
	}
}
