// Copyright 2021 Google LLC
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

package subnet

import (
	"context"
	"encoding/json"
	"net"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/cilium/cilium/pkg/testutils"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/testing/protocmp"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	apiruntime "k8s.io/apimachinery/pkg/runtime"
	k8sFake "k8s.io/client-go/kubernetes/fake"
	k8sTesting "k8s.io/client-go/testing"
)

// mockNetwork is used within tests that require some setup of mock links and
// addresses.
type mockNetwork struct {
	Link  netlink.Link
	Addrs []*netlink.Addr
}

func Test_annotateNodeSubnets(t *testing.T) {
	testutils.PrivilegedTest(t)
	tests := map[string]struct {
		mockNetworks []mockNetwork
		nodeIPv4     net.IP
		nodeIPv6     net.IP
		node         *corev1.Node
		wantPatch    *corev1.Node
	}{
		"applies IPv4 subnet": {
			mockNetworks: []mockNetwork{
				{
					Link: linkNamed("test0"),
					Addrs: []*netlink.Addr{
						netlinkAddrGlobal(t, "192.168.1.1/24"),
					},
				},
			},
			node: &corev1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: "node",
				},
			},
			nodeIPv4: parseIP(t, "192.168.1.1"),
			wantPatch: &corev1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						IPv4SubnetAnnotationKey: "192.168.1.1/24",
						IPv6SubnetAnnotationKey: "",
					},
				},
			},
		},
		"applies IPv6 subnet": {
			mockNetworks: []mockNetwork{
				{
					Link: linkNamed("test0"),
					Addrs: []*netlink.Addr{
						netlinkAddrGlobal(t, "2001::1/64"),
					},
				},
			},
			node: &corev1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: "node",
				},
			},
			nodeIPv6: parseIP(t, "2001::1"),
			wantPatch: &corev1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						IPv4SubnetAnnotationKey: "",
						IPv6SubnetAnnotationKey: "2001::1/64",
					},
				},
			},
		},
		"applies both subnets on same interface": {
			mockNetworks: []mockNetwork{
				{
					Link: linkNamed("test0"),
					Addrs: []*netlink.Addr{
						netlinkAddrGlobal(t, "192.168.1.1/24"),
						netlinkAddrGlobal(t, "2001::1/64"),
					},
				},
			},
			node: &corev1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: "node",
				},
			},
			nodeIPv4: parseIP(t, "192.168.1.1"),
			nodeIPv6: parseIP(t, "2001::1"),
			wantPatch: &corev1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						IPv4SubnetAnnotationKey: "192.168.1.1/24",
						IPv6SubnetAnnotationKey: "2001::1/64",
					},
				},
			},
		},
		"applies both subnets on different interfaces": {
			mockNetworks: []mockNetwork{
				{
					Link: linkNamed("test0"),
					Addrs: []*netlink.Addr{
						netlinkAddrGlobal(t, "192.168.1.1/24"),
					},
				},
				{
					Link: linkNamed("test1"),
					Addrs: []*netlink.Addr{
						netlinkAddrGlobal(t, "2001::1/64"),
					},
				},
			},
			node: &corev1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: "node",
				},
			},
			nodeIPv4: parseIP(t, "192.168.1.1"),
			nodeIPv6: parseIP(t, "2001::1"),
			wantPatch: &corev1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						IPv4SubnetAnnotationKey: "192.168.1.1/24",
						IPv6SubnetAnnotationKey: "2001::1/64",
					},
				},
			},
		},
		"ignores non-global IPv6 address": {
			mockNetworks: []mockNetwork{
				{
					Link: linkNamed("test0"),
					Addrs: []*netlink.Addr{
						netlinkAddrGlobal(t, "192.168.1.1/24"),
						netlinkAddrLocal(t, "fe80::1/64"),
					},
				},
			},
			node: &corev1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: "node",
				},
			},
			nodeIPv4: parseIP(t, "192.168.1.1"),
			nodeIPv6: parseIP(t, "fe80::1"),
			wantPatch: &corev1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						IPv4SubnetAnnotationKey: "192.168.1.1/24",
						IPv6SubnetAnnotationKey: "",
					},
				},
			},
		},
		"chooses correct subnets from many": {
			mockNetworks: []mockNetwork{
				{
					Link: linkNamed("test0"),
					Addrs: []*netlink.Addr{
						netlinkAddrGlobal(t, "192.168.0.1/24"),
						netlinkAddrGlobal(t, "192.168.1.1/25"),
						netlinkAddrGlobal(t, "192.168.2.1/26"),
						netlinkAddrGlobal(t, "192.168.3.1/27"),
						netlinkAddrGlobal(t, "192.168.4.1/28"),
						netlinkAddrGlobal(t, "2000::1/65"),
						netlinkAddrGlobal(t, "2001::1/66"),
						netlinkAddrGlobal(t, "2002::1/67"),
						netlinkAddrGlobal(t, "2003::1/68"),
						netlinkAddrGlobal(t, "2004::1/69"),
					},
				},
			},
			node: &corev1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: "node",
				},
			},
			nodeIPv4: parseIP(t, "192.168.3.1"),
			nodeIPv6: parseIP(t, "2003::1"),
			wantPatch: &corev1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						IPv4SubnetAnnotationKey: "192.168.3.1/27",
						IPv6SubnetAnnotationKey: "2003::1/68",
					},
				},
			},
		},
		"chooses correct links from many": {
			mockNetworks: []mockNetwork{
				{
					Link: linkNamed("test0"),
					Addrs: []*netlink.Addr{
						netlinkAddrGlobal(t, "192.168.0.1/24"),
						netlinkAddrGlobal(t, "2000::1/64"),
					},
				},
				{
					Link: linkNamed("test1"),
					Addrs: []*netlink.Addr{
						netlinkAddrGlobal(t, "192.168.1.1/25"),
						netlinkAddrGlobal(t, "2001::1/65"),
					},
				},
				{
					Link: linkNamed("test2"),
					Addrs: []*netlink.Addr{
						netlinkAddrGlobal(t, "192.168.2.1/26"),
						netlinkAddrGlobal(t, "2002::1/66"),
					},
				},
				{
					Link: linkNamed("test3"),
					Addrs: []*netlink.Addr{
						netlinkAddrGlobal(t, "192.168.3.1/27"),
						netlinkAddrGlobal(t, "2003::1/67"),
					},
				},
				{
					Link: linkNamed("test4"),
					Addrs: []*netlink.Addr{
						netlinkAddrGlobal(t, "192.168.4.1/28"),
						netlinkAddrGlobal(t, "2004::1/68"),
					},
				},
			},
			node: &corev1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: "node",
				},
			},
			nodeIPv4: parseIP(t, "192.168.2.1"),
			nodeIPv6: parseIP(t, "2003::1"),
			wantPatch: &corev1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						IPv4SubnetAnnotationKey: "192.168.2.1/26",
						IPv6SubnetAnnotationKey: "2003::1/67",
					},
				},
			},
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			runFuncInNetNS(t, func() {
				applyMockNetworks(t, tc.mockNetworks)

				client := &k8sFake.Clientset{}
				nodeName := tc.node.Name

				// Other examples use a channel for this but we are testing a function
				// that blocks until the patch is complete. This reactor will run
				// synchronously.
				var patchesRequested int
				client.AddReactor("patch", "nodes", func(action k8sTesting.Action) (handled bool, ret apiruntime.Object, err error) {
					patchesRequested++

					pa := action.(k8sTesting.PatchAction)
					if pa.GetName() != nodeName {
						t.Fatalf("Action %s was not for correct node name %s", pa.GetName(), nodeName)
					}

					// Check incoming patch.
					bytes := pa.GetPatch()
					gotPatch := &corev1.Node{}

					if err := json.Unmarshal(bytes, &gotPatch); err != nil {
						t.Fatalf("Could not unmarshal patch: %v", err)
					}

					if diff := cmp.Diff(gotPatch, tc.wantPatch, protocmp.Transform()); diff != "" {
						t.Errorf("Patch action did not match expected (-got, +want):\n%s", diff)
					}

					return true, nil, nil
				})

				if err := annotateNodeSubnets(context.TODO(), client, nodeName, tc.nodeIPv4, tc.nodeIPv6); err != nil {
					t.Fatalf("annotateNodeSubnets failed: %v", err)
				}
				if patchesRequested != 1 {
					t.Fatalf("Expected one patch to be applied, got %d", patchesRequested)
				}
			})
		})
	}
}

func Test_annotateNodeSubnetsErrors(t *testing.T) {
	testutils.PrivilegedTest(t)
	tests := map[string]struct {
		mockNetworks   []mockNetwork
		nodeIPv4       net.IP
		nodeIPv6       net.IP
		node           *corev1.Node
		wantErrMatches string
	}{
		"no match on IPv4 subnet": {
			mockNetworks: []mockNetwork{
				{
					Link: linkNamed("test0"),
					Addrs: []*netlink.Addr{
						netlinkAddrGlobal(t, "192.168.100.1/24"),
						netlinkAddrGlobal(t, "2001::1/64"),
					},
				},
			},
			node: &corev1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: "node",
				},
			},
			nodeIPv4:       parseIP(t, "192.168.1.1"),
			wantErrMatches: "No subnets found",
		},
		"no match on IPv6 subnet": {
			mockNetworks: []mockNetwork{
				{
					Link: linkNamed("test0"),
					Addrs: []*netlink.Addr{
						netlinkAddrGlobal(t, "192.168.1.1/24"),
						netlinkAddrGlobal(t, "2002::1/64"),
					},
				},
			},
			node: &corev1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: "node",
				},
			},
			nodeIPv6:       parseIP(t, "2001::1"),
			wantErrMatches: "No subnets found",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			runFuncInNetNS(t, func() {
				applyMockNetworks(t, tc.mockNetworks)

				client := &k8sFake.Clientset{}
				nodeName := tc.node.Name

				// Other examples use a channel for this but we are testing a function
				// that blocks until the patch is complete. This reactor will run
				// synchronously.
				var patchesRequested int
				client.AddReactor("patch", "nodes", func(action k8sTesting.Action) (handled bool, ret apiruntime.Object, err error) {
					patchesRequested++
					return true, nil, nil
				})

				err := annotateNodeSubnets(context.TODO(), client, nodeName, tc.nodeIPv4, tc.nodeIPv6)
				if !strings.Contains(err.Error(), tc.wantErrMatches) {
					t.Fatalf("Expected annotateNodeSubnets error to match: %q not found in %q", tc.wantErrMatches, err.Error())
				}
				if patchesRequested != 0 {
					t.Fatalf("Expected no patches to be applied, got %d", patchesRequested)
				}
			})
		})
	}
}

func Test_patchForSubnetAnnotation(t *testing.T) {
	tests := map[string]struct {
		ipv4Subnet *net.IPNet
		ipv6Subnet *net.IPNet
		wantPatch  *corev1.Node
	}{
		"applies IPv4 subnet": {
			ipv4Subnet: parseIPNet(t, "192.168.1.1/24"),
			ipv6Subnet: nil,
			wantPatch: &corev1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						IPv4SubnetAnnotationKey: "192.168.1.1/24",
						IPv6SubnetAnnotationKey: "",
					},
				},
			},
		},
		"applies IPv6 subnet": {
			ipv4Subnet: nil,
			ipv6Subnet: parseIPNet(t, "2001::1/64"),
			wantPatch: &corev1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						IPv4SubnetAnnotationKey: "",
						IPv6SubnetAnnotationKey: "2001::1/64",
					},
				},
			},
		},
		"applies both subnets": {
			ipv4Subnet: parseIPNet(t, "192.168.1.1/24"),
			ipv6Subnet: parseIPNet(t, "2001::1/64"),
			wantPatch: &corev1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						IPv4SubnetAnnotationKey: "192.168.1.1/24",
						IPv6SubnetAnnotationKey: "2001::1/64",
					},
				},
			},
		},
		"wipes both subnets when missing": {
			ipv4Subnet: nil,
			ipv6Subnet: nil,
			wantPatch: &corev1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						IPv4SubnetAnnotationKey: "",
						IPv6SubnetAnnotationKey: "",
					},
				},
			},
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			patchBytes, err := patchForSubnetAnnotations(test.ipv4Subnet, test.ipv6Subnet)
			if err != nil {
				t.Fatalf("patchForSubnetAnnotations failed: %v", err)
			}

			gotPatch := &corev1.Node{}
			if err := json.Unmarshal(patchBytes, &gotPatch); err != nil {
				t.Fatalf("Could not unmarshal patch: %v", err)
			}
			if !reflect.DeepEqual(gotPatch, test.wantPatch) {
				t.Fatalf("Patch did not match expected: patchBytes: %q", string(patchBytes))
			}
		})
	}
}

func Test_patchForSubnetAnnotationErrors(t *testing.T) {
	testutils.PrivilegedTest(t)

	tests := map[string]struct {
		ipv4Subnet     *net.IPNet
		ipv6Subnet     *net.IPNet
		wantErrMatches string
	}{
		"subnetIPv4 is wrong family": {
			ipv4Subnet:     parseIPNet(t, "fe80::1/64"),
			ipv6Subnet:     nil,
			wantErrMatches: "ipv4 subnet is incorrect family",
		},
		"subnetIPv6 is wrong family": {
			ipv4Subnet:     nil,
			ipv6Subnet:     parseIPNet(t, "192.168.1.1/24"),
			wantErrMatches: "ipv6 subnet is incorrect family",
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := patchForSubnetAnnotations(tc.ipv4Subnet, tc.ipv6Subnet)
			if !strings.Contains(err.Error(), tc.wantErrMatches) {
				t.Fatalf("Expected patchForSubnetAnnotations error to match: %q not found in %q", tc.wantErrMatches, err.Error())
			}
		})
	}
}

func Test_subnetFor(t *testing.T) {
	testutils.PrivilegedTest(t)
	tests := map[string]struct {
		mockNetworks []mockNetwork
		ip           net.IP
		wantSubnet   *net.IPNet
	}{
		"finds link and address associated with IPv4 address": {
			mockNetworks: []mockNetwork{
				{
					Link: linkNamed("test0"),
					Addrs: []*netlink.Addr{
						netlinkAddrGlobal(t, "192.168.1.1/24"),
						netlinkAddrGlobal(t, "192.168.1.2/24"),
						netlinkAddrGlobal(t, "2001::1/64"),
						netlinkAddrGlobal(t, "2001::2/64"),
					},
				},
			},
			ip:         parseIP(t, "192.168.1.1"),
			wantSubnet: parseIPNet(t, "192.168.1.1/24"),
		},
		"finds link and address associated with IPv6 address": {
			mockNetworks: []mockNetwork{
				{
					Link: linkNamed("test0"),
					Addrs: []*netlink.Addr{
						netlinkAddrGlobal(t, "192.168.1.1/24"),
						netlinkAddrGlobal(t, "192.168.1.2/24"),
						netlinkAddrGlobal(t, "2001::1/64"),
						netlinkAddrGlobal(t, "2001::2/64"),
					},
				},
			},
			ip:         parseIP(t, "2001::1"),
			wantSubnet: parseIPNet(t, "2001::1/64"),
		},
		"finds correct link out of many": {
			mockNetworks: []mockNetwork{
				{
					Link: linkNamed("test0"),
					Addrs: []*netlink.Addr{
						netlinkAddrGlobal(t, "192.168.0.1/24"),
						netlinkAddrGlobal(t, "192.168.0.2/24"),
					},
				},
				{
					Link: linkNamed("test1"),
					Addrs: []*netlink.Addr{
						netlinkAddrGlobal(t, "192.168.1.1/24"),
						netlinkAddrGlobal(t, "192.168.1.2/24"),
					},
				},
				{
					Link: linkNamed("test2"),
					Addrs: []*netlink.Addr{
						netlinkAddrGlobal(t, "192.168.2.1/24"),
						netlinkAddrGlobal(t, "192.168.2.2/24"),
					},
				},
				{
					Link: linkNamed("test3"),
					Addrs: []*netlink.Addr{
						netlinkAddrGlobal(t, "192.168.3.1/24"),
						netlinkAddrGlobal(t, "192.168.3.2/24"),
					},
				},
			},
			ip:         parseIP(t, "192.168.2.1"),
			wantSubnet: parseIPNet(t, "192.168.2.1/24"),
		},
		"returns nil for nil IP": {
			ip:         nil,
			wantSubnet: nil,
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			runFuncInNetNS(t, func() {
				applyMockNetworks(t, tc.mockNetworks)

				gotSubnet, err := subnetFor(tc.ip)
				if err != nil {
					t.Fatalf("Error from subnetFor(%s) : %v", tc.ip, err)
				}

				ignoreLabel := cmpopts.IgnoreFields(netlink.Addr{}, "Label")
				if diff := cmp.Diff(gotSubnet, tc.wantSubnet, ignoreLabel); diff != "" {
					t.Errorf("Matching subnet differed from expected (-got, +want):\n%s", diff)
				}
			})
		})
	}
}

func Test_subnetForErrors(t *testing.T) {
	testutils.PrivilegedTest(t)
	tests := map[string]struct {
		mockNetworks   []mockNetwork
		ip             net.IP
		wantErrMatches string
	}{
		"gives err when IP matches addr with non-global scope": {
			mockNetworks: []mockNetwork{
				{
					Link: linkNamed("test0"),
					Addrs: []*netlink.Addr{
						netlinkAddrLocal(t, "fe80::1/64"),
					},
				},
			},
			ip:             parseIP(t, "fe80::1"),
			wantErrMatches: "found address for IP but it is not universal scope",
		},
		"gives err when IP is not found on any interfaces": {
			mockNetworks: []mockNetwork{
				{
					Link: linkNamed("test0"),
					Addrs: []*netlink.Addr{
						netlinkAddrGlobal(t, "192.168.1.2/24"),
					},
				},
			},
			ip:             parseIP(t, "192.168.1.1"),
			wantErrMatches: "failed to find link",
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			runFuncInNetNS(t, func() {
				applyMockNetworks(t, tc.mockNetworks)

				_, err := subnetFor(tc.ip)
				if !strings.Contains(err.Error(), tc.wantErrMatches) {
					t.Fatalf("Expected subnetFor(%s) error to match: %q not found in %q", tc.ip.String(), tc.wantErrMatches, err.Error())
				}
			})
		})
	}
}

func runFuncInNetNS(t *testing.T, run func()) {
	// Source:
	// https://github.com/vishvananda/netlink/blob/c79a4b7b40668c3f7867bf256b80b6b2dc65e58e/netns_test.go#L49
	runtime.LockOSThread() // We need a constant OS thread
	defer runtime.UnlockOSThread()

	currentNS, err := netns.Get()
	if err != nil {
		t.Fatalf("Failed to get network namespace: %v", err)
	}
	defer func(h netns.NsHandle) {
		if err := netns.Set(h); err != nil {
			t.Fatalf("Failed to set network namespace: %v", err)
		}
	}(currentNS)

	networkNS, err := netns.New()
	if err != nil {
		t.Fatalf("Failed to get new network namespace: %v", err)
	}
	defer func(h netns.NsHandle) {
		if err := h.Close(); err != nil {
			t.Fatalf("Failed to close network namespace: %v", err)
		}
	}(networkNS)

	run()
}

// applyMockNetworks applies mockNetworks to the current network namespace.
func applyMockNetworks(t *testing.T, mockNetworks []mockNetwork) {
	for _, mock := range mockNetworks {
		linkName := mock.Link.Attrs().Name
		if err := netlink.LinkAdd(mock.Link); err != nil {
			t.Fatalf("TEST BUG: failed to add placeholder link %q", linkName)
		}
		link, err := netlink.LinkByName(linkName)
		if err != nil {
			t.Fatalf("TEST BUG: failed to get placeholder link %q", linkName)
		}
		for _, addr := range mock.Addrs {
			if err := netlink.AddrAdd(link, addr); err != nil {
				t.Fatalf("TEST BUG: failed to add address %q to placeholder link %s", addr, linkName)
			}
		}
	}
}

// parseIP converts an ip string to net.IP.
func parseIP(t *testing.T, ipStr string) net.IP {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		t.Fatalf("TEST BUG: failed to parse IP %q", ipStr)
	}
	return ip
}

// parseIP converts a CIDR string to net.IPNet.
func parseIPNet(t *testing.T, cidr string) *net.IPNet {
	ip, net, err := net.ParseCIDR(cidr)
	if err != nil {
		t.Fatalf("TEST BUG: failed to parse CIDR %q", cidr)
	}
	net.IP = ip
	return net
}

func netlinkAddrGlobal(t *testing.T, cidr string) *netlink.Addr {
	return &netlink.Addr{
		IPNet: parseIPNet(t, cidr),
		Scope: unix.RT_SCOPE_UNIVERSE,
	}
}

func netlinkAddrLocal(t *testing.T, cidr string) *netlink.Addr {
	return &netlink.Addr{
		IPNet: parseIPNet(t, cidr),
		Scope: unix.RT_SCOPE_LINK,
	}
}

func linkNamed(name string) netlink.Link {
	return &netlink.Dummy{
		LinkAttrs: netlink.LinkAttrs{
			Name: name,
		},
	}
}
