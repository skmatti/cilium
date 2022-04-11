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

package dhcp

import (
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/rpc"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/containernetworking/cni/pkg/skel"
	cnitypes "github.com/containernetworking/cni/pkg/types"
	ipam "github.com/containernetworking/cni/pkg/types/100"
	"github.com/google/go-cmp/cmp"
	networkv1alpha1 "gke-internal.googlesource.com/anthos-networking/apis/v2/network/v1alpha1"
	"k8s.io/utils/pointer"
)

var (
	containerID   = "12345"
	podNS         = "pod-ns"
	podIfName     = "net1"
	podMACAddress = "af:af:af:af:af:af"
	parentIfName  = "vlan100"
)

type DHCP struct {
	server *rpc.Server
	lis    net.Listener
	// svcError controls whether the grpc call needs to return error.
	svcError bool
	//allocateResult is the result that will be returned when Allocated is called
	allocateResult *ipam.Result
	// expectedMacAddress is the expected mac address that is sent in the CmdArgs
	expectedMacAddress *string
	t                  *testing.T
}

func (f *DHCP) Allocate(args *skel.CmdArgs, result *ipam.Result) error {
	if args.ContainerID != containerID {
		f.t.Errorf("incorrect container ID. Got %s, expected %s", args.ContainerID, containerID)
	}
	netns, err := filepath.Abs(podNS)
	if err != nil {
		f.t.Fatalf("failed to make %q an absolute path: %s", args.Netns, err)
	}
	if args.Netns != netns {
		f.t.Errorf("incorrect pod ns. Got %s, expected %s", args.Netns, podNS)
	}
	if args.IfName != podIfName {
		f.t.Errorf("incorrect pod interface. Got %s, expected %s", args.IfName, podIfName)
	}
	expectedArgs := ""
	if f.expectedMacAddress != nil && *f.expectedMacAddress != "" {
		expectedArgs = fmt.Sprintf("parentInterface=%s;macAddress=%s", parentIfName, *f.expectedMacAddress)
	} else {
		expectedArgs = fmt.Sprintf("parentInterface=%s", parentIfName)
	}
	if args.Args != expectedArgs {
		f.t.Errorf("incorrect args. Got %s, expected %s", args.Args, expectedArgs)
	}
	if f.svcError {
		return errors.New("rpc error")
	}

	*result = *f.allocateResult
	return nil
}

func (f *DHCP) Release(args *skel.CmdArgs, reply *struct{}) error {
	if args.ContainerID != containerID {
		f.t.Errorf("incorrect container ID. Got %s, expected %s", args.ContainerID, containerID)
	}
	netns, err := filepath.Abs(podNS)
	if err != nil {
		f.t.Fatalf("failed to make %q an absolute path: %s", args.Netns, err)
	}
	if args.Netns != netns {
		f.t.Errorf("incorrect pod ns. Got %s, expected %s", args.Netns, podNS)
	}
	if args.IfName != podIfName {
		f.t.Errorf("incorrect pod inerface. Got %s, expected %s", args.IfName, podIfName)
	}
	if args.Args != leaseExpireArgs {
		f.t.Errorf("incorrect args. Got %s, expected %s", args.Args, leaseExpireArgs)
	}
	if f.svcError {
		return errors.New("rpc error")
	}
	return nil
}

// setUpDHCPClient sets up the environment for testing DHCPClient.
// The function creates a local unix socket and listener to the socket.
func setUpDHCPClient(t *testing.T) (string, string, *DHCP, error) {
	var socketDir string //, socket string
	socketDir, err := ioutil.TempDir("", "dhcp-client")
	if err != nil {
		return "", "", nil, err
	}

	// Assemble the full path of the unix socket.
	path := filepath.Join(socketDir, "dhcp.sock")

	lis, err := net.Listen("unix", path)
	if err != nil {
		return socketDir, "", nil, err
	}
	fakeServer := &DHCP{server: rpc.NewServer(), lis: lis, t: t}
	rpc.Register(fakeServer)
	rpc.HandleHTTP()
	go http.Serve(lis, nil)
	return socketDir, path, fakeServer, nil
}

func dhcpTearDown(path string, fakeServer *DHCP) error {
	if fakeServer != nil {
		fakeServer.lis.Close()
	}
	// reset http default serve mux for next test
	rpc.DefaultServer = rpc.NewServer()
	http.DefaultServeMux = http.NewServeMux()
	return os.RemoveAll(path)
}

func TestGetDHCPResponse(t *testing.T) {
	socketDir, testDHCPSocket, fakeServer, err := setUpDHCPClient(t)
	if err != nil {
		t.Fatalf("setUpDHCPClient() failed: %v", err)
	}
	defer func() {
		if err := dhcpTearDown(socketDir, fakeServer); err != nil {
			t.Errorf("dhcpTearDown() failed: %v", err)
		}
	}()
	_, cidr1, err := net.ParseCIDR("3.3.3.3/24")
	if err != nil {
		t.Fatalf("failed to parse cidr1 in setup")
	}
	_, cidr2, err := net.ParseCIDR("4.4.4.4/24")
	if err != nil {
		t.Fatalf("failed to parse cidr2 in setup")
	}
	_, ipNet, err := net.ParseCIDR("1.1.1.1/24")
	if err != nil {
		t.Fatalf("failed to parse ip  cidr in setup")
	}
	gw := net.ParseIP("2.2.2.2")

	result := &ipam.Result{
		IPs: []*ipam.IPConfig{{Address: *ipNet, Gateway: gw}},
		Routes: []*cnitypes.Route{
			{Dst: *cidr1, GW: gw},
			{Dst: *cidr2, GW: gw},
			{GW: gw},
		},
		DNS: cnitypes.DNS{
			Nameservers: []string{"5.5.5.5", "6.6.6.6"},
			Search:      []string{"example.com", "example.org"},
		},
	}

	missingIPResult := &ipam.Result{
		Routes: result.Routes,
		DNS:    result.DNS,
	}
	missingDNSResult := &ipam.Result{
		IPs:    result.IPs,
		Routes: result.Routes,
	}
	missingRoutesResult := &ipam.Result{
		IPs: result.IPs,
		DNS: result.DNS,
	}
	testcases := []struct {
		desc string
		want *DHCPResponse
		// response the DHCP daemon returns
		dhcpResult *ipam.Result
		rpcErr     bool
		wantErr    string
		macAddress *string
	}{
		{
			desc: "converted dhcp response properly",
			want: &DHCPResponse{
				IPAddresses: []*net.IPNet{ipNet},
				Gateway4:    pointer.StringPtr("2.2.2.2"),
				Routes: []networkv1alpha1.Route{
					{To: cidr1.String()},
					{To: cidr2.String()},
				},
				DNSConfig: &networkv1alpha1.DNSConfig{
					Nameservers: []string{"5.5.5.5", "6.6.6.6"},
					Searches:    []string{"example.com", "example.org"},
				},
			},
			dhcpResult: result,
			macAddress: pointer.StringPtr(podMACAddress),
		},
		{
			desc: "empty ip",
			want: &DHCPResponse{
				Routes: []networkv1alpha1.Route{
					{To: cidr1.String()},
					{To: cidr2.String()},
				},
				DNSConfig: &networkv1alpha1.DNSConfig{
					Nameservers: []string{"5.5.5.5", "6.6.6.6"},
					Searches:    []string{"example.com", "example.org"},
				},
			},
			dhcpResult: missingIPResult,
			macAddress: pointer.StringPtr(podMACAddress),
		},
		{
			desc: "empty dns",
			want: &DHCPResponse{
				IPAddresses: []*net.IPNet{ipNet},
				Gateway4:    pointer.StringPtr("2.2.2.2"),
				Routes: []networkv1alpha1.Route{
					{To: "3.3.3.0/24"},
					{To: "4.4.4.0/24"},
				},
				DNSConfig: nil,
			},
			dhcpResult: missingDNSResult,
			macAddress: pointer.StringPtr(podMACAddress),
		},
		{
			desc: "no routes",
			want: &DHCPResponse{
				IPAddresses: []*net.IPNet{ipNet},
				Gateway4:    pointer.StringPtr("2.2.2.2"),
				DNSConfig: &networkv1alpha1.DNSConfig{
					Nameservers: []string{"5.5.5.5", "6.6.6.6"},
					Searches:    []string{"example.com", "example.org"},
				},
			},
			dhcpResult: missingRoutesResult,
			macAddress: pointer.StringPtr(podMACAddress),
		},
		{
			desc:       "reponse errored",
			wantErr:    "error calling",
			rpcErr:     true,
			macAddress: pointer.StringPtr(podMACAddress),
		},
		{
			desc: "does not add the macAddress if is nil",
			want: &DHCPResponse{
				IPAddresses: []*net.IPNet{ipNet},
				Gateway4:    pointer.StringPtr("2.2.2.2"),
				Routes: []networkv1alpha1.Route{
					{To: cidr1.String()},
					{To: cidr2.String()},
				},
				DNSConfig: &networkv1alpha1.DNSConfig{
					Nameservers: []string{"5.5.5.5", "6.6.6.6"},
					Searches:    []string{"example.com", "example.org"},
				},
			},
			dhcpResult: result,
			macAddress: nil,
		},
		{
			desc: "does not add the macAddress if is empty",
			want: &DHCPResponse{
				IPAddresses: []*net.IPNet{ipNet},
				Gateway4:    pointer.StringPtr("2.2.2.2"),
				Routes: []networkv1alpha1.Route{
					{To: cidr1.String()},
					{To: cidr2.String()},
				},
				DNSConfig: &networkv1alpha1.DNSConfig{
					Nameservers: []string{"5.5.5.5", "6.6.6.6"},
					Searches:    []string{"example.com", "example.org"},
				},
			},
			dhcpResult: result,
			macAddress: pointer.StringPtr(""),
		},
	}
	for _, tc := range testcases {
		t.Run(tc.desc, func(t *testing.T) {
			fakeServer.svcError = tc.rpcErr
			fakeServer.allocateResult = tc.dhcpResult
			fakeServer.expectedMacAddress = tc.macAddress
			dc := newDHCPClientWithSocket(testDHCPSocket)
			got, gotErr := dc.GetDHCPResponse(containerID, podNS, podIfName, parentIfName, tc.macAddress)
			if gotErr != nil {
				if tc.wantErr == "" {
					t.Fatalf("dc.Allocate() returns error %v but want nil", gotErr)
				}
				if !strings.Contains(gotErr.Error(), tc.wantErr) {
					t.Fatalf("dc.Allocate() returns error %v but want %v", gotErr, tc.wantErr)
				}
				return
			}

			if tc.wantErr != "" {
				t.Fatalf("dc.Allocate() returns nil but want error %v", tc.wantErr)
			}

			if diff := cmp.Diff(got, tc.want); diff != "" {
				t.Fatalf("dc.Allocate() returns unexpected output (-got, +want):\n%s", diff)
			}
		})
	}
}

func TestDHCPRelease(t *testing.T) {
	socketDir, testDHCPSocket, fakeServer, err := setUpDHCPClient(t)
	if err != nil {
		t.Fatalf("setUpDHCPClient() failed: %v", err)
	}
	defer func() {
		if err := dhcpTearDown(socketDir, fakeServer); err != nil {
			t.Errorf("dhcpTearDown() failed: %v", err)
		}
	}()
	testcases := []struct {
		desc    string
		rpcErr  bool
		wantErr string
	}{
		{
			desc: "successful release call",
		},
		{
			desc:    "rpc error",
			rpcErr:  true,
			wantErr: "errored in rpc call DHCP.Release",
		},
	}
	for _, tc := range testcases {
		t.Run(tc.desc, func(t *testing.T) {
			fakeServer.svcError = tc.rpcErr
			dc := newDHCPClientWithSocket(testDHCPSocket)
			gotErr := dc.Release(containerID, podNS, podIfName)
			if gotErr != nil {
				if tc.wantErr == "" {
					t.Fatalf("dc.Release() returns error %v but want nil", gotErr)
				}
				if !strings.Contains(gotErr.Error(), tc.wantErr) {
					t.Fatalf("dc.Release() returns error %v but want %v", gotErr, tc.wantErr)
				}
				return
			}

			if tc.wantErr != "" {
				t.Fatalf("dc.Release() returns nil but want error %v", tc.wantErr)
			}
		})
	}
}

// TestNilRPCClient ensures that when the dhcpClient does not have a configured rpc client
// which can occur if the socket is not found at initialization, that the dhcpClient on demand
// will create a connection to the socket which will be used for requests to the DHCPPlugin.
func TestNilRPCClient(t *testing.T) {
	socketDir, testDHCPSocket, fakeServer, err := setUpDHCPClient(t)
	if err != nil {
		t.Fatalf("setUpDHCPClient() failed: %v", err)
	}
	defer func() {
		if err := dhcpTearDown(socketDir, fakeServer); err != nil {
			t.Errorf("dhcpTearDown() failed: %v", err)
		}
	}()
	result := &ipam.Result{}
	fakeServer.allocateResult = result
	macAddr := pointer.StringPtr(podMACAddress)
	fakeServer.expectedMacAddress = macAddr
	dc := &dhcpClient{socketPath: testDHCPSocket}
	_, gotErr := dc.GetDHCPResponse(containerID, podNS, podIfName, parentIfName, macAddr)
	if gotErr != nil {
		t.Fatalf("dc.Allocate() returns error %v but want nil", gotErr)
	}

	dc.client = nil
	gotErr = dc.Release(containerID, podNS, podIfName)
	if gotErr != nil {
		t.Fatalf("dc.Release() returns error %v but want nil", gotErr)
	}
}
