//go:build !privileged_tests
// +build !privileged_tests

package types

import (
	"strings"
	"testing"

	"github.com/cilium/cilium/pkg/cidr"
	"github.com/cilium/cilium/pkg/node"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	networkv1 "k8s.io/cloud-provider-gcp/crd/apis/network/v1"
)

func TestBuildMultiNetworkCIDRs(t *testing.T) {
	testCases := []struct {
		desc         string
		annotation   string
		wantNetworks map[string]*cidr.CIDR
		wantErr      string
	}{
		{
			desc:       "failure, invalid multi-networking annotation format",
			annotation: "invalid-annotation",
			wantErr:    "invalid format for multi-network annotation",
		},
		{
			desc:       "failure, invalid network cidr in annotation",
			annotation: `[{"name":"my-network", "cidrs":["10.0.00/21"],"scope":"host-local"}]`,
			wantErr:    "invalid network cidr 10.0.00/21",
		},
		{
			desc:       "failure, ipv6 network cidr in annotation",
			annotation: `[{"name":"my-network", "cidrs":["fd02:1::/32"],"scope":"host-local"}]`,
			wantErr:    "only networks with ipv4 addresses are supported",
		},
		{
			desc:       "success, valid annotation",
			annotation: `[{"name":"my-network", "cidrs":["10.0.0.0/21"],"scope":"host-local"}, {"name":"bar", "cidrs":["20.0.0.0/21"],"scope":"host-local"}]`,
			wantNetworks: map[string]*cidr.CIDR{
				"my-network": cidr.MustParseCIDR("10.0.0.0/21"),
				"bar":        cidr.MustParseCIDR("20.0.0.0/21"),
			},
		},
	}

	for _, tc := range testCases {
		res, err := BuildMultiNetworkCIDRs(tc.annotation)
		if err != nil && tc.wantErr == "" {
			t.Fatalf("BuildMultiNetworkCIDRs() returned error %v but want nil", err)
		}
		if tc.wantErr != "" {
			if err == nil {
				t.Fatalf("BuildMultiNetworkCIDRs() returned nil but want error %v", tc.wantErr)
			}
			if !strings.HasPrefix(err.Error(), tc.wantErr) {
				t.Fatalf("BuildMultiNetworkCIDRs() returned error %v but want error %v", err.Error(), tc.wantErr)
			}
		}
		if tc.wantNetworks == nil && res != nil {
			t.Fatalf("BuildMultiNetworkCIDRs() returned %v but want nil networks", res)
		}
		if tc.wantNetworks != nil {
			for nw, wantCIDR := range tc.wantNetworks {
				resCIDR, ok := res[nw]
				if !ok {
					t.Fatalf("network %s is missing in the result networks", nw)
				}
				if resCIDR.IP.String() != wantCIDR.IP.String() {
					t.Fatalf("incorrect IP for network %s, got %s, want %s", nw, resCIDR.IP.String(), wantCIDR.IP.String())
				}
				if resCIDR.Mask.String() != wantCIDR.Mask.String() {
					t.Fatalf("incorrect mask for network %s, got %s, want %s", nw, resCIDR.Mask.String(), wantCIDR.Mask.String())
				}
			}
		}
	}
}

func TestInterfaceName(t *testing.T) {
	testCases := []struct {
		desc     string
		network  *networkv1.Network
		wantName string
		wantErr  string
	}{
		{
			desc: "valid",
			network: &networkv1.Network{
				ObjectMeta: v1.ObjectMeta{
					Name: "nic1",
				},
				Spec: networkv1.NetworkSpec{
					Type: networkv1.L3NetworkType,
				},
			},
			wantName: "lo",
			wantErr:  "",
		},
		{
			desc: "invalid, no matching interface",
			network: &networkv1.Network{
				ObjectMeta: v1.ObjectMeta{
					Name: "nic2",
				},
				Spec: networkv1.NetworkSpec{
					Type: networkv1.L3NetworkType,
				},
			},
			wantName: "",
			wantErr:  "matching interface does not exist for network nic2 with IP 127.1.0.0",
		},
		{
			desc: "invalid, network not found in annotation",
			network: &networkv1.Network{
				ObjectMeta: v1.ObjectMeta{
					Name: "abc",
				},
				Spec: networkv1.NetworkSpec{
					Type: networkv1.L3NetworkType,
				},
			},
			wantName: "",
			wantErr:  "network abc not found in north interfaces annotation",
		},
	}

	for _, tc := range testCases {
		niAnnotation := []networkv1.NorthInterface{
			{
				Network:   "nic1",
				IpAddress: "127.0.0.1",
			},
			{
				Network:   "nic2",
				IpAddress: "127.1.0.0",
			},
		}
		niAnnotationString, err := networkv1.MarshalNorthInterfacesAnnotation(niAnnotation)
		if err != nil {
			t.Fatalf("error: %v", err)
		}
		var annotations = map[string]string{
			networkv1.NorthInterfacesAnnotationKey: niAnnotationString,
		}
		node.SetAnnotations(annotations)
		infName, err := InterfaceName(tc.network)
		if err != nil && tc.wantErr != err.Error() {
			t.Fatalf("want err %v, got err %v", tc.wantErr, err)
		}
		if infName != tc.wantName {
			t.Fatalf("incorrect interface name, want %s got %s", tc.wantName, infName)
		}
	}
}
