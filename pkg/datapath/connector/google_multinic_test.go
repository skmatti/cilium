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

//go:build privileged_tests
// +build privileged_tests

package connector

import (
	"errors"
	"fmt"
	"net"
	"runtime"
	"strings"
	"testing"

	"github.com/cilium/cilium/pkg/gke/multinic/dhcp"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	networkv1alpha1 "gke-internal.googlesource.com/anthos-networking/apis/v2/network/v1alpha1"
	"golang.org/x/sys/unix"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/pointer"

	_ "gopkg.in/check.v1"
)

const (
	goodIPv4Str       = "1.2.3.4/24"
	goodIPv4StrNoMask = "1.2.3.4"
	badIPv4Str        = "1"
	goodIPv6Str       = "a:b::/32"
	goodIPv6StrNoMask = "a:b::"
	dummyLinkName     = "dummy"
	dummyLinkIP       = "172.168.10.1"
	dummyLinkMask     = 24
	remoteNSName      = "test"
)

func getTestInterfaceCR(ipStrs []string, macStr *string) *networkv1alpha1.NetworkInterface {
	return &networkv1alpha1.NetworkInterface{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-eth0",
			Namespace: "test-ns",
		},
		Spec: networkv1alpha1.NetworkInterfaceSpec{
			IpAddresses: ipStrs,
			MacAddress:  macStr,
		},
	}
}

func getTestInterfaceCRWithStatus(ipStrs []string, macStr *string, statusMacStr string) *networkv1alpha1.NetworkInterface {
	intfCR := getTestInterfaceCR(ipStrs, macStr)
	intfCR.Status.MacAddress = statusMacStr
	return intfCR
}

func getTestNetworkCR(parentDevName *string) *networkv1alpha1.Network {
	return &networkv1alpha1.Network{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-network",
		},
		Spec: networkv1alpha1.NetworkSpec{
			NodeInterfaceMatcher: networkv1alpha1.NodeInterfaceMatcher{
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

// setupDummyInterfaceInRemoteNS creates a new remote network namespace
// and a dummy interface in the remote ns.
// The function switches the current ns and reverts afterwards.
func setupDummyInterfaceInRemoteNS(t *testing.T) (netlink.Link, string, func() error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	currentNS, err := netns.Get()
	if err != nil {
		t.Fatalf("failed to get current network namespace: %v", err)
	}
	defer netns.Set(currentNS)

	remoteNS, err := netns.NewNamed(remoteNSName)
	if err != nil {
		t.Fatalf("failed to create test network namespace: %v", err)
	}
	defer remoteNS.Close()

	dummy := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: dummyLinkName}}
	err = netlink.LinkAdd(dummy)
	if err != nil {
		t.Fatalf("unable to add parent interface: %v", err)
	}

	if err := applyIPToLink(&net.IPNet{
		IP:   net.ParseIP(dummyLinkIP),
		Mask: net.CIDRMask(dummyLinkMask, 32),
	}, dummy); err != nil {
		t.Fatalf("unable to apply IP address: %v", err)
	}

	return dummy, fmt.Sprint("/var/run/netns/", remoteNSName), func() error {
		return netns.DeleteNamed(remoteNSName)
	}
}

func v4Route(ip, gw string, mask, mtu int, scope netlink.Scope) netlink.Route {
	route := netlink.Route{
		LinkIndex: 2,
		Scope:     scope,
		Dst: &net.IPNet{
			IP:   net.ParseIP(ip).To4(),
			Mask: net.CIDRMask(mask, 32),
		},
		Protocol: netlink.RouteProtocol(unix.RTPROT_BOOT),
		Family:   netlink.FAMILY_V4,
		Table:    unix.RT_TABLE_MAIN,
		Type:     unix.RTN_UNICAST,
		MTU:      mtu,
	}
	if gw != "" {
		route.Gw = net.ParseIP(gw)
	}
	return route
}

func v4DefaultRoute(gw string) netlink.Route {
	dr := v4Route("", gw, 0, 0, netlink.SCOPE_UNIVERSE)
	dr.Dst = nil
	return dr
}

func dummyLinkRoute() netlink.Route {
	route := v4Route("172.168.10.0", "", dummyLinkMask, 0, netlink.SCOPE_LINK)
	route.Src = net.ParseIP(dummyLinkIP)
	route.Protocol = 2
	return route
}

func TestGetInterfaceConfiguration(t *testing.T) {
	parentDevName := "parent-dev"
	parentDevNameEmpty := ""
	goodMACStr := "01:02:03:04:05:06"
	badMACStr := "ff"
	testcases := []struct {
		desc    string
		wantErr string
		intf    *networkv1alpha1.NetworkInterface
		net     *networkv1alpha1.Network
		want    *interfaceConfiguration
	}{
		{
			desc: "parse successfully",
			intf: getTestInterfaceCR([]string{goodIPv4Str}, &goodMACStr),
			net:  getTestNetworkCR(&parentDevName),
			want: &interfaceConfiguration{
				ParentInterfaceName: parentDevName,
				IPV4Address: &net.IPNet{
					IP:   net.IPv4(1, 2, 3, 4),
					Mask: net.IPv4Mask(255, 255, 255, 0),
				},
				MacAddress: net.HardwareAddr([]byte{1, 2, 3, 4, 5, 6}),
			},
		},
		{
			desc:    "two ipv4 address",
			intf:    getTestInterfaceCR([]string{goodIPv4Str, goodIPv4Str}, &goodMACStr),
			net:     getTestNetworkCR(&parentDevName),
			wantErr: "Only single IPv4 address is supported for macvlan/macvtap interface",
		},
		{
			desc: "empty ipv4 address list",
			intf: getTestInterfaceCR([]string{}, &goodMACStr),
			net:  getTestNetworkCR(&parentDevName),
			want: &interfaceConfiguration{
				ParentInterfaceName: parentDevName,
				MacAddress:          net.HardwareAddr([]byte{1, 2, 3, 4, 5, 6}),
			},
		},
		{
			desc: "nil ipv4 address list",
			intf: getTestInterfaceCR(nil, &goodMACStr),
			net:  getTestNetworkCR(&parentDevName),
			want: &interfaceConfiguration{
				ParentInterfaceName: parentDevName,
				MacAddress:          net.HardwareAddr([]byte{1, 2, 3, 4, 5, 6}),
			},
		},
		{
			desc: "no mac address in spec and status",
			intf: getTestInterfaceCR([]string{goodIPv4Str}, nil),
			net:  getTestNetworkCR(&parentDevName),
			want: &interfaceConfiguration{
				ParentInterfaceName: parentDevName,
				IPV4Address: &net.IPNet{
					IP:   net.IPv4(1, 2, 3, 4),
					Mask: net.IPv4Mask(255, 255, 255, 0),
				},
			},
		},
		{
			desc: "no mac address in spec but in status",
			intf: getTestInterfaceCRWithStatus([]string{goodIPv4Str}, nil, goodMACStr),
			net:  getTestNetworkCR(&parentDevName),
			want: &interfaceConfiguration{
				ParentInterfaceName: parentDevName,
				IPV4Address: &net.IPNet{
					IP:   net.IPv4(1, 2, 3, 4),
					Mask: net.IPv4Mask(255, 255, 255, 0),
				},
				MacAddress: net.HardwareAddr([]byte{1, 2, 3, 4, 5, 6}),
			},
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

			if tc.wantErr != "" {
				t.Fatalf("getInterfaceConfiguration() returns nil but want %v", tc.wantErr)
			}

			if s := cmp.Diff(got, tc.want); s != "" {
				t.Fatalf("getInterfaceConfiguration() returns unexpected output (-got, +want): %s", s)
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
			wantErr: "IPV6 is not supported for macvlan/macvtap interface",
		},
		{
			desc:    "unsupported ipv6 address without mask",
			addr:    goodIPv6StrNoMask,
			wantErr: "IPV6 is not supported for macvlan/macvtap interface",
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

func TestParseIPRoutes(t *testing.T) {
	testcases := []struct {
		desc    string
		routes  []networkv1alpha1.Route
		want    []*net.IPNet
		wantErr string
	}{
		{
			desc: "good routes",
			routes: []networkv1alpha1.Route{
				{To: goodIPv4Str},
				{To: "10.10.10.1/32"},
			},
			want: []*net.IPNet{
				{IP: net.ParseIP("1.2.3.0"), Mask: net.CIDRMask(24, 32)},
				{IP: net.ParseIP("10.10.10.1"), Mask: net.CIDRMask(32, 32)},
			},
		},
		{
			desc: "parse cidr fail",
			routes: []networkv1alpha1.Route{
				{To: "192.168.0.10.10"},
			},
			wantErr: "failed to parse CIDR: invalid CIDR address: 192.168.0.10.10",
		},
		{
			desc: "reject default route",
			routes: []networkv1alpha1.Route{
				{To: "0.0.0.0/0"},
			},
			wantErr: "CIDR length must be over 0: 0.0.0.0/0",
		},
		{
			desc: "reject route with 0 prefix length",
			routes: []networkv1alpha1.Route{
				{To: "10.10.0.0/0"},
			},
			wantErr: "CIDR length must be over 0: 10.10.0.0/0",
		},
		{
			desc: "reject ipv6 route",
			routes: []networkv1alpha1.Route{
				{To: goodIPv6Str},
			},
			wantErr: "ipv6 route \"a:b::/32\" is not supported",
		},
	}
	for _, tc := range testcases {
		t.Run(tc.desc, func(t *testing.T) {
			got, gotErr := parseIPRoutes(tc.routes)
			if gotErr != nil {
				if len(tc.wantErr) == 0 {
					t.Fatalf("parseIPRoutes() returns error %v but want nil", gotErr)
				}
				if gotErr.Error() != tc.wantErr {
					t.Fatalf("parseIPRoutes() returns error %v but want %v", gotErr, tc.wantErr)
				}
				return
			}
			if diff := cmp.Diff(got, tc.want); diff != "" {
				t.Fatalf("parseIPRoutes() output differed (-got, +want):\n%s", diff)
			}
		})
	}
}

func TestSetupNetworkRoutes(t *testing.T) {
	v4GW := "172.168.10.253"
	v6GW := "a::1"
	invalidGW := "invalid_gw"
	testcases := []struct {
		desc               string
		interfaceName      string
		intf               *networkv1alpha1.NetworkInterface
		isDefaultInterface bool
		routeMTU           int
		wantRoutes         []netlink.Route
		wantErr            string
	}{
		{
			desc: "apply routes with gw to multinic-network",
			intf: &networkv1alpha1.NetworkInterface{
				Status: networkv1alpha1.NetworkInterfaceStatus{
					Routes: []networkv1alpha1.Route{
						{
							To: "10.10.10.0/24",
						},
						{
							To: "20.20.20.0/24",
						},
					},
					Gateway4: &v4GW,
				},
			},
			wantRoutes: []netlink.Route{
				v4Route("10.10.10.0", v4GW, 24, 0, netlink.SCOPE_UNIVERSE),
				v4Route("20.20.20.0", v4GW, 24, 0, netlink.SCOPE_UNIVERSE),
			},
		},
		{
			desc: "apply routes without gw to multinic-network",
			intf: &networkv1alpha1.NetworkInterface{
				Status: networkv1alpha1.NetworkInterfaceStatus{
					Routes: []networkv1alpha1.Route{
						{
							To: "10.10.10.0/24",
						},
						{
							To: "20.20.20.0/24",
						},
					},
				},
			},
			wantRoutes: []netlink.Route{
				v4Route("10.10.10.0", "", 24, 0, netlink.SCOPE_LINK),
				v4Route("20.20.20.0", "", 24, 0, netlink.SCOPE_LINK),
			},
		},
		{
			desc: "apply default route with gw to multinic-network",
			intf: &networkv1alpha1.NetworkInterface{
				Status: networkv1alpha1.NetworkInterfaceStatus{
					Routes: []networkv1alpha1.Route{
						{
							To: "10.10.10.0/24",
						},
						{
							To: "20.20.20.0/24",
						},
					},
					Gateway4: &v4GW,
				},
			},
			isDefaultInterface: true,
			wantRoutes: []netlink.Route{
				v4Route("10.10.10.0", v4GW, 24, 0, netlink.SCOPE_UNIVERSE),
				v4Route("20.20.20.0", v4GW, 24, 0, netlink.SCOPE_UNIVERSE),
				v4DefaultRoute(v4GW),
			},
		},
		{
			desc: "apply default route with gw to pod-network",
			intf: &networkv1alpha1.NetworkInterface{
				Spec: networkv1alpha1.NetworkInterfaceSpec{
					NetworkName: networkv1alpha1.DefaultNetworkName,
				},
				Status: networkv1alpha1.NetworkInterfaceStatus{
					Routes: []networkv1alpha1.Route{
						{
							To: "10.10.10.0/24",
						},
						{
							To: "20.20.20.0/24",
						},
					},
					Gateway4: &v4GW,
				},
			},
			isDefaultInterface: true,
			wantRoutes: []netlink.Route{
				v4Route("10.10.10.0", v4GW, 24, 0, netlink.SCOPE_UNIVERSE),
				v4Route("20.20.20.0", v4GW, 24, 0, netlink.SCOPE_UNIVERSE),
			},
		},
		{
			desc: "apply routes with mtu to multinic-network",
			intf: &networkv1alpha1.NetworkInterface{
				Status: networkv1alpha1.NetworkInterfaceStatus{
					Routes: []networkv1alpha1.Route{
						{
							To: "10.10.10.0/24",
						},
						{
							To: "20.20.20.0/24",
						},
					},
				},
			},
			routeMTU: 1300,
			wantRoutes: []netlink.Route{
				v4Route("10.10.10.0", "", 24, 0, netlink.SCOPE_LINK),
				v4Route("20.20.20.0", "", 24, 0, netlink.SCOPE_LINK),
			},
		},
		{
			desc: "apply routes with mtu to pod-network",
			intf: &networkv1alpha1.NetworkInterface{
				Spec: networkv1alpha1.NetworkInterfaceSpec{
					NetworkName: networkv1alpha1.DefaultNetworkName,
				},
				Status: networkv1alpha1.NetworkInterfaceStatus{
					Routes: []networkv1alpha1.Route{
						{
							To: "10.10.10.0/24",
						},
						{
							To: "20.20.20.0/24",
						},
					},
				},
			},
			routeMTU: 1300,
			wantRoutes: []netlink.Route{
				v4Route("10.10.10.0", "", 24, 1300, netlink.SCOPE_LINK),
				v4Route("20.20.20.0", "", 24, 1300, netlink.SCOPE_LINK),
			},
		},
		{
			desc:       "no routes to apply",
			intf:       &networkv1alpha1.NetworkInterface{Status: networkv1alpha1.NetworkInterfaceStatus{}},
			wantRoutes: []netlink.Route{},
		},
		{
			desc: "invalid routes",
			intf: &networkv1alpha1.NetworkInterface{
				Status: networkv1alpha1.NetworkInterfaceStatus{
					Routes: []networkv1alpha1.Route{
						{
							To: "invalid_route",
						},
					},
				},
			},
			wantErr: "failed to parse IP routes for the interface CR \"\": failed to parse CIDR: invalid CIDR address: invalid_route",
		},
		{
			desc: "invalid gw",
			intf: &networkv1alpha1.NetworkInterface{
				Status: networkv1alpha1.NetworkInterfaceStatus{
					Gateway4: &invalidGW,
				},
			},
			wantErr: "failed to get a valid IPv4 gateway address: invalid_gw",
		},
		{
			desc: "v6 gw",
			intf: &networkv1alpha1.NetworkInterface{
				Status: networkv1alpha1.NetworkInterfaceStatus{
					Gateway4: &v6GW,
				},
			},
			wantErr: "failed to get a valid IPv4 gateway address: a::1",
		},
		{
			desc:          "interface not found",
			interfaceName: "net1",
			intf:          &networkv1alpha1.NetworkInterface{},
			wantErr:       "failed to lookup interface \"net1\": Link not found",
		},
		{
			desc: "default route but without gw address",
			intf: &networkv1alpha1.NetworkInterface{
				Status: networkv1alpha1.NetworkInterfaceStatus{
					Gateway4: nil,
				},
			},
			isDefaultInterface: true,
			wantErr:            "default route must have a valid gateway address",
		},
	}

	for _, tc := range testcases {
		t.Run(tc.desc, func(t *testing.T) {
			var err error
			dummyLink, testNSPath, deleteNSFunc := setupDummyInterfaceInRemoteNS(t)
			defer func() {
				if err := deleteNSFunc(); err != nil {
					t.Fatalf("deleting test network namespace failed %v", err)
				}
			}()

			testNS, err := ns.GetNS(testNSPath)
			if err != nil {
				t.Fatalf("failed to open test network namespace: %v", err)
			}
			defer testNS.Close()

			interfaceNameInPod := dummyLinkName
			if tc.interfaceName != "" {
				interfaceNameInPod = tc.interfaceName
			}

			// Run the test in the root ns.
			gotErr := SetupNetworkRoutes(interfaceNameInPod, tc.intf, testNS.Path(), tc.isDefaultInterface, tc.routeMTU)
			if gotErr != nil {
				if tc.wantErr == "" {
					t.Fatalf("SetupNetworkRoutes() return error %v but want nil", gotErr)
				}
				if gotErr.Error() != tc.wantErr {
					t.Fatalf("SetupNetworkRoutes() return error %v but want %v", gotErr, tc.wantErr)
				}
				return
			}

			var gotRoutes []netlink.Route
			if err := testNS.Do(func(_ ns.NetNS) error {
				gotRoutes, err = netlink.RouteList(dummyLink, netlink.FAMILY_V4)
				if err != nil {
					return err
				}
				return nil
			}); err != nil {
				t.Fatalf("failed to list routes: %v", err)
			}

			tc.wantRoutes = append(tc.wantRoutes, dummyLinkRoute())
			if diff := cmp.Diff(gotRoutes, tc.wantRoutes, cmpopts.SortSlices(func(r1, r2 netlink.Route) bool {
				return r1.String() < r2.String()
			})); diff != "" {
				t.Fatalf("SetupNetworkRoutes() apply unexpected routes (-got, +want)\n%s", diff)
			}
		})
	}
}

func TestConfigureDHCPInfo(t *testing.T) {
	trueVal := true
	parentInt := "vlan100"
	dhcpNetwork := &networkv1alpha1.Network{
		Spec: networkv1alpha1.NetworkSpec{
			NodeInterfaceMatcher: networkv1alpha1.NodeInterfaceMatcher{
				InterfaceName: &parentInt,
			},
			ExternalDHCP4: &trueVal,
		},
	}
	routesNetwork := &networkv1alpha1.Network{
		Spec: networkv1alpha1.NetworkSpec{
			NodeInterfaceMatcher: networkv1alpha1.NodeInterfaceMatcher{
				InterfaceName: &parentInt,
			},
			ExternalDHCP4: &trueVal,
			Routes:        []networkv1alpha1.Route{{To: "route1"}},
		},
	}
	nameServersNetwork := &networkv1alpha1.Network{
		Spec: networkv1alpha1.NetworkSpec{
			NodeInterfaceMatcher: networkv1alpha1.NodeInterfaceMatcher{
				InterfaceName: &parentInt,
			},
			ExternalDHCP4: &trueVal,
			DNSConfig: &networkv1alpha1.DNSConfig{
				Nameservers: []string{"1.1.1.1", "2.2.2.2"},
			},
		},
	}
	searchesNetwork := &networkv1alpha1.Network{
		Spec: networkv1alpha1.NetworkSpec{
			NodeInterfaceMatcher: networkv1alpha1.NodeInterfaceMatcher{
				InterfaceName: &parentInt,
			},
			ExternalDHCP4: &trueVal,
			DNSConfig: &networkv1alpha1.DNSConfig{
				Searches: []string{"example.com", "example.org"},
			},
		},
	}
	gatewayNetwork := &networkv1alpha1.Network{
		Spec: networkv1alpha1.NetworkSpec{
			NodeInterfaceMatcher: networkv1alpha1.NodeInterfaceMatcher{
				InterfaceName: &parentInt,
			},
			ExternalDHCP4: &trueVal,
			Gateway4:      pointer.StringPtr("3.3.3.3"),
		},
	}
	staticNetwork := &networkv1alpha1.Network{}
	missingIntNetwork := &networkv1alpha1.Network{
		Spec: networkv1alpha1.NetworkSpec{
			ExternalDHCP4: &trueVal,
		},
	}
	l2Network := &networkv1alpha1.Network{
		Spec: networkv1alpha1.NetworkSpec{
			NodeInterfaceMatcher: networkv1alpha1.NodeInterfaceMatcher{
				InterfaceName: &parentInt,
			},
			L2NetworkConfig: &networkv1alpha1.L2NetworkConfig{
				VlanID: pointer.Int32(100),
			},
			ExternalDHCP4: &trueVal,
		},
	}

	_, ipNet1, err := net.ParseCIDR("1.2.3.4/24")
	if err != nil {
		t.Fatalf("failed to parse cidr: %s", err)
	}
	_, ipNet2, err := net.ParseCIDR("2.2.3.4/24")
	if err != nil {
		t.Fatalf("failed to parse cidr: %s", err)
	}
	mac, err := net.ParseMAC("aa:aa:aa:aa:aa:aa")
	if err != nil {
		t.Fatalf("failed to parse mac address: %s", err)
	}

	staticIP := interfaceConfiguration{
		IPV4Address: ipNet1,
	}

	staticMAC := interfaceConfiguration{
		MacAddress: mac,
	}

	emptyConfig := interfaceConfiguration{}
	dhcpConfig := interfaceConfiguration{
		IPV4Address: ipNet2,
	}
	dhcpConfigWithMac := interfaceConfiguration{
		IPV4Address: ipNet2,
		MacAddress:  mac,
	}

	dhcpResp := dhcp.DHCPResponse{
		IPAddresses: []*net.IPNet{ipNet2},
		Routes: []networkv1alpha1.Route{
			{To: "route2"},
		},
		DNSConfig: &networkv1alpha1.DNSConfig{
			Nameservers: []string{"10.10.10.10"},
			Searches:    []string{"searchdomain"},
		},
		Gateway4: pointer.StringPtr("gateway"),
	}
	emptyMacResponse := dhcp.DHCPResponse{
		IPAddresses: []*net.IPNet{ipNet2},
		Routes: []networkv1alpha1.Route{
			{To: "route3"},
		},
		DNSConfig: &networkv1alpha1.DNSConfig{
			Nameservers: []string{"10.10.10.10"},
			Searches:    []string{"searchdomain"},
		},
		Gateway4: pointer.StringPtr("gateway"),
	}

	fakeClient := &fakeDHCPClient{
		emptyMacResponse: emptyMacResponse,
		resp:             dhcpResp,
	}

	testcases := []struct {
		desc     string
		network  *networkv1alpha1.Network
		cfg      interfaceConfiguration
		wantResp *dhcp.DHCPResponse
		wantErr  string
		wantCfg  interfaceConfiguration
		dc       *fakeDHCPClient
	}{
		{
			desc:     "network specifies external DHCP and no static config",
			network:  dhcpNetwork,
			cfg:      emptyConfig,
			dc:       fakeClient,
			wantResp: &emptyMacResponse,
			wantCfg:  dhcpConfig,
		},
		{
			desc:     "network specifies external DHCP with l2NetworkConfig",
			network:  l2Network,
			cfg:      emptyConfig,
			dc:       fakeClient,
			wantResp: &emptyMacResponse,
			wantCfg:  dhcpConfig,
		},
		{
			desc:    "network specifies external DHCP and no static config, and no IP is returned",
			network: dhcpNetwork,
			cfg:     emptyConfig,
			dc: &fakeDHCPClient{
				emptyMacResponse: dhcp.DHCPResponse{},
				resp:             dhcp.DHCPResponse{},
			},
			wantResp: nil,
			wantCfg:  emptyConfig,
			wantErr:  "dhcp response does not have any ip addresses",
		},
		{
			desc:     "network specifies external DHCP and with static IP",
			network:  dhcpNetwork,
			cfg:      staticIP,
			dc:       fakeClient,
			wantResp: nil,
			wantErr:  "static IP requested when static information is not provided in network",
			wantCfg:  staticIP,
		},
		{
			desc:     "network specifies external DHCP with static mac",
			network:  dhcpNetwork,
			cfg:      staticMAC,
			dc:       fakeClient,
			wantResp: &dhcpResp,
			wantCfg:  dhcpConfigWithMac,
		},
		{
			desc:     "network specifies external DHCP and routes info with static ip",
			network:  routesNetwork,
			cfg:      staticIP,
			dc:       fakeClient,
			wantResp: nil,
			wantCfg:  staticIP,
		},
		{
			desc:     "network specifies external DHCP and nameserver dns info with static ip",
			network:  nameServersNetwork,
			cfg:      staticIP,
			dc:       fakeClient,
			wantResp: nil,
			wantCfg:  staticIP,
		},
		{
			desc:     "network specifies external DHCP and searches dns info with static ip",
			network:  searchesNetwork,
			cfg:      staticIP,
			dc:       fakeClient,
			wantResp: nil,
			wantCfg:  staticIP,
		},
		{
			desc:     "network specifies external DHCP and gateway info with static ip",
			network:  gatewayNetwork,
			cfg:      staticIP,
			dc:       fakeClient,
			wantResp: nil,
			wantCfg:  staticIP,
		},
		{
			desc:     "network doesn't specify externalDHCP and has no IP",
			network:  staticNetwork,
			cfg:      emptyConfig,
			dc:       fakeClient,
			wantResp: nil,
			wantCfg:  emptyConfig,
		},
		{
			desc:    "network specifies externalDHCP and has no interface name",
			network: missingIntNetwork,
			cfg:     emptyConfig,
			dc:      fakeClient,
			wantCfg: emptyConfig,
			wantErr: "failed to configure dhcp info for : invalid network : network.spec.nodeInterfaceMatcher.InterfaceName cannot be nil or empty",
		},
		{
			desc:    "dhcp client errors",
			network: dhcpNetwork,
			cfg:     emptyConfig,
			dc: &fakeDHCPClient{
				emptyMacResponse: dhcp.DHCPResponse{},
				resp:             dhcp.DHCPResponse{},
				clientErr:        errors.New("dhcp client error"),
			},
			wantErr: "dhcp client error",
			wantCfg: emptyConfig,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.desc, func(t *testing.T) {
			// create copy of config, so original is not modified and does not cause test pollution
			testCfg := tc.cfg
			tc.dc.network = tc.network
			tc.dc.t = t
			gotResp, gotErr := configureDHCPInfo(tc.network, &testCfg, tc.dc, "podNS", "podIface", "containerID")

			if diff := cmp.Diff(gotResp, tc.wantResp); diff != "" {
				t.Errorf("configureDHCPInfo() has incorrect dhcp response (-got, +want): %s\n", diff)
			}

			if tc.wantErr != "" {
				if gotErr == nil {
					t.Errorf("configureDHCPInfo() should have returned an error")
					return
				}
				if diff := cmp.Diff(gotErr.Error(), tc.wantErr); diff != "" {
					t.Errorf("configureDHCPInfo() returned incorrect error (-got, +want): %s\n", diff)
					return
				}
				return
			}
			if gotErr != nil {
				t.Errorf("configureDHCPInfo() returned unexpected error: %s", err)
			}
			if diff := cmp.Diff(testCfg, tc.wantCfg); diff != "" {
				t.Errorf("configureDHCPInfo() has incorrect interfaceConfiguration (-got, +want): %s\n", diff)
			}
		})
	}
}

type fakeDHCPClient struct {
	emptyMacResponse dhcp.DHCPResponse
	resp             dhcp.DHCPResponse
	clientErr        error
	network          *networkv1alpha1.Network
	t                *testing.T
}

func (dc *fakeDHCPClient) GetDHCPResponse(containerID, podNS, podIface, parentIface string, macAddress *string) (*dhcp.DHCPResponse, error) {
	if dc.clientErr != nil {
		return nil, dc.clientErr
	}

	expectedParentIface, err := dc.network.InterfaceName()
	if err != nil {
		dc.t.Fatalf("errored getting parent interface from network %+v: %s", dc.network, err)
	}
	if parentIface != expectedParentIface {
		dc.t.Fatalf("GetDHCPResponse was passed parentIface %s, but expected %s", parentIface, expectedParentIface)
	}

	if macAddress == nil || *macAddress == "" {
		return &dc.emptyMacResponse, nil
	}

	return &dc.resp, nil
}

func (dc *fakeDHCPClient) Release(containerID, podNS, podIface string) error {
	return dc.clientErr
}
