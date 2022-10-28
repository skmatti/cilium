//go:build !privileged_tests
// +build !privileged_tests

package types

import (
	"strings"
	"testing"

	"github.com/cilium/cilium/pkg/cidr"
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
