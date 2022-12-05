//go:build privileged_tests
// +build privileged_tests

package cmd

import (
	"net"
	"strings"
	"testing"

	"github.com/cilium/cilium/pkg/datapath/fake"
	"github.com/cilium/cilium/pkg/ipam"
	ipamOption "github.com/cilium/cilium/pkg/ipam/option"
	"github.com/cilium/cilium/pkg/k8s/watchers"
	"github.com/cilium/cilium/pkg/mtu"
	"github.com/cilium/cilium/pkg/nodediscovery"
	"github.com/cilium/cilium/pkg/option"
	networkv1 "k8s.io/cloud-provider-gcp/crd/apis/network/v1"
)

func TestUpdateMultiNetworkIPAMAllocators(t *testing.T) {
	option.Config.IPAM = ipamOption.IPAMKubernetes
	d := Daemon{datapath: fake.NewDatapath(), nodeDiscovery: &nodediscovery.NodeDiscovery{}, k8sWatcher: &watchers.K8sWatcher{}, mtuConfig: mtu.Configuration{}}
	d.startIPAM()

	testCases := []struct {
		desc               string
		nodeAnnotations    map[string]string
		existingAllocators map[string]ipam.Allocator
		wantAllocators     map[string]ipam.Allocator
		wantError          string
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
		},
		{
			desc:            "updates to existing allocators",
			nodeAnnotations: map[string]string{networkv1.MultiNetworkAnnotationKey: `[{"name":"bar", "cidrs":["20.0.0.0/21"],"scope":"host-local"}]`},
			existingAllocators: map[string]ipam.Allocator{
				"my-network": ipam.NewHostScopeAllocator(&net.IPNet{IP: net.IPv4(10, 0, 0, 0), Mask: net.IPv4Mask(255, 255, 224, 0)}),
			},
			wantAllocators: map[string]ipam.Allocator{
				"bar": ipam.NewHostScopeAllocator(&net.IPNet{IP: net.IPv4(20, 0, 0, 0), Mask: net.IPv4Mask(255, 255, 224, 0)}),
			},
		},
	}

	for _, tc := range testCases {
		// set existing allocators per test case
		d.ipam.MultiNetworkAllocators = tc.existingAllocators
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
		for nw := range d.ipam.MultiNetworkAllocators {
			if _, ok := tc.wantAllocators[nw]; !ok {
				t.Fatalf("expected ipam allocator for network %s to be absent, but is present", nw)
			}
		}
	}
}
