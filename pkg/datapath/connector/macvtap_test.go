// Copyright 2021 Authors of Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build !privileged_tests
// +build !privileged_tests

package connector

import (
	"net"
	"strings"
	"testing"

	multinicv1alpha1 "github.com/cilium/cilium/pkg/gke/apis/multinic/v1alpha1"
	"github.com/google/go-cmp/cmp"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	goodIPv4Str       = "1.2.3.4/24"
	goodIPv4StrNoMask = "1.2.3.4"
	badIPv4Str        = "1"
	goodIPv6Str       = "a:b::/32"
	goodIPv6StrNoMask = "a:b::"
)

func getTestInterfaceCR(ipStrs []string, macStr *string) *multinicv1alpha1.NetworkInterface {
	return &multinicv1alpha1.NetworkInterface{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-eth0",
			Namespace: "test-ns",
		},
		Spec: multinicv1alpha1.NetworkInterfaceSpec{
			IpAddresses: ipStrs,
			MacAddress:  macStr,
		},
	}
}

func getTestNetworkCR(parentDevName *string) *multinicv1alpha1.Network {
	return &multinicv1alpha1.Network{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-network",
		},
		Spec: multinicv1alpha1.NetworkSpec{
			NodeInterfaceMatcher: multinicv1alpha1.NodeInterfaceMatcher{
				InterfaceName: parentDevName,
			},
		},
	}
}

func errorContains(got error, want string) bool {
	if want == "" {
		return false
	}
	return strings.Contains(got.Error(), want)
}

func TestGetInterfaceConfiguration(t *testing.T) {
	parentDevName := "parent-dev"
	parentDevNameEmpty := ""
	goodMACStr := "01:02:03:04:05:06"
	badMACStr := "ff"
	testcases := []struct {
		desc    string
		wantErr string
		intf    *multinicv1alpha1.NetworkInterface
		net     *multinicv1alpha1.Network
	}{
		{
			desc: "parse successfully",
			intf: getTestInterfaceCR([]string{goodIPv4Str}, &goodMACStr),
			net:  getTestNetworkCR(&parentDevName),
		},
		{
			desc:    "two ipv4 address",
			intf:    getTestInterfaceCR([]string{goodIPv4Str, goodIPv4Str}, &goodMACStr),
			net:     getTestNetworkCR(&parentDevName),
			wantErr: "Only single IPv4 address is supported for macvtap interface",
		},
		{
			desc:    "empty ipv4 address list",
			intf:    getTestInterfaceCR([]string{}, &goodMACStr),
			net:     getTestNetworkCR(&parentDevName),
			wantErr: "Only single IPv4 address is supported for macvtap interface",
		},
		{
			desc:    "nil ipv4 address list",
			intf:    getTestInterfaceCR(nil, &goodMACStr),
			net:     getTestNetworkCR(&parentDevName),
			wantErr: "Only single IPv4 address is supported for macvtap interface",
		},
		{
			desc:    "no mac address",
			intf:    getTestInterfaceCR([]string{goodIPv4Str}, nil),
			net:     getTestNetworkCR(&parentDevName),
			wantErr: "no Mac address is found in the interface CR",
		},
		{
			desc:    "no parent interface name",
			intf:    getTestInterfaceCR([]string{goodIPv4Str}, &goodMACStr),
			net:     getTestNetworkCR(nil),
			wantErr: "parent interface name is not found in the network CR",
		},
		{
			desc:    "invalid ip address",
			intf:    getTestInterfaceCR([]string{badIPv4Str}, &goodMACStr),
			net:     getTestNetworkCR(&parentDevName),
			wantErr: "failed to get a valid IP in the interface CR",
		},
		{
			desc:    "unsupported ipv6 address",
			intf:    getTestInterfaceCR([]string{goodIPv6Str}, &goodMACStr),
			net:     getTestNetworkCR(&parentDevName),
			wantErr: "failed to get a valid IP in the interface CR",
		},
		{
			desc:    "invalid mac address",
			intf:    getTestInterfaceCR([]string{goodIPv4Str}, &badMACStr),
			net:     getTestNetworkCR(&parentDevName),
			wantErr: "unable to parse MAC in the interface CR",
		},
		{
			desc:    "empty parent interface name",
			intf:    getTestInterfaceCR([]string{goodIPv4Str}, &goodMACStr),
			net:     getTestNetworkCR(&parentDevNameEmpty),
			wantErr: "parent interface name is empty in the network CR",
		},
	}
	for _, tc := range testcases {
		t.Run(tc.desc, func(t *testing.T) {
			got, gotErr := getInterfaceConfiguration(tc.intf, tc.net)
			if gotErr != nil {
				if len(tc.wantErr) == 0 {
					t.Fatalf("getInterfaceConfiguration() returns error %v but want nil", gotErr)
				}
				if !errorContains(gotErr, tc.wantErr) {
					t.Fatalf("getInterfaceConfiguration() returns error %v but want %v", gotErr, tc.wantErr)
				}
				return
			}

			want := &interfaceConfiguration{
				IPV4Address: &net.IPNet{
					IP:   net.IPv4(1, 2, 3, 4),
					Mask: net.IPv4Mask(255, 255, 255, 0),
				},
				MacAddress:          net.HardwareAddr([]byte{1, 2, 3, 4, 5, 6}),
				ParentInterfaceName: parentDevName,
			}
			if s := cmp.Diff(want, got); s != "" {
				t.Fatalf("getInterfaceConfiguration() returns unexpected output (-want, +got): %s", s)
			}
		})
	}
}

func TestParseIPSubnet(t *testing.T) {
	testcases := []struct {
		desc    string
		addr    string
		wantErr string
	}{
		{
			desc: "good ipv4 address with mask",
			addr: goodIPv4Str,
		},
		{
			desc: "good ipv4 address without mask",
			addr: goodIPv4StrNoMask,
		},
		{
			desc:    "invalid ipv4 address",
			addr:    badIPv4Str,
			wantErr: "failed to parse IP",
		},
		{
			desc:    "unsupported ipv6 address",
			addr:    goodIPv6Str,
			wantErr: "IPV6 is not supported for macvtap interface",
		},
		{
			desc:    "unsupported ipv6 address without mask",
			addr:    goodIPv6StrNoMask,
			wantErr: "IPV6 is not supported for macvtap interface",
		},
	}
	for _, tc := range testcases {
		t.Run(tc.desc, func(t *testing.T) {
			got, gotErr := parseIPSubnet(tc.addr)
			if gotErr != nil {
				if len(tc.wantErr) == 0 {
					t.Fatalf("parseIPSubnet(%s) returns error %v but want nil", tc.addr, gotErr)
				}
				if !errorContains(gotErr, tc.wantErr) {
					t.Fatalf("parseIPSubnet(%s) returns error %v but want %v", tc.addr, gotErr, tc.wantErr)
				}
				return
			}

			var mask net.IPMask
			if tc.addr == goodIPv4StrNoMask {
				mask = net.IPv4Mask(255, 255, 255, 255)
			} else {
				mask = net.IPv4Mask(255, 255, 255, 0)
			}
			want := &net.IPNet{
				IP:   net.ParseIP(goodIPv4StrNoMask),
				Mask: mask,
			}
			if got.String() != want.String() {
				t.Fatalf("parseIPSubnet(%s) returns %q but want %q", tc.addr, got, want)
			}
		})
	}
}
