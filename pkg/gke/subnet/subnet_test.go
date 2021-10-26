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

//go:build privileged_tests
// +build privileged_tests

package subnet

import (
	"context"
	"encoding/json"
	"net"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	k8sFake "k8s.io/client-go/kubernetes/fake"
	k8sTesting "k8s.io/client-go/testing"

	. "gopkg.in/check.v1"
)

func Test(t *testing.T) { TestingT(t) }

type SubnetAnnotationSuite struct{}

var _ = Suite(&SubnetAnnotationSuite{})

// mockNetwork is used within tests that require some setup of mock links and
// addresses.
type mockNetwork struct {
	Link  netlink.Link
	Addrs []*netlink.Addr
}

func (s *SubnetAnnotationSuite) Test_annotateNodeSubnets(c *C) {
	tests := map[string]struct {
		mockNetworks   []mockNetwork
		nodeIPv4       net.IP
		nodeIPv6       net.IP
		node           *corev1.Node
		wantPatch      *corev1.Node
		wantErrMatches string
	}{
		"[happy] applies IPv4 subnet": {
			mockNetworks: []mockNetwork{
				{
					Link: linkNamed("test0"),
					Addrs: []*netlink.Addr{
						netlinkAddrGlobal(c, "192.168.1.1/24"),
					},
				},
			},
			node: &corev1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: "node",
				},
			},
			nodeIPv4: parseIP(c, "192.168.1.1"),
			wantPatch: &corev1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						IPv4SubnetAnnotationKey: "192.168.1.1/24",
						IPv6SubnetAnnotationKey: "",
					},
				},
			},
		},
		"[happy] applies IPv6 subnet": {
			mockNetworks: []mockNetwork{
				{
					Link: linkNamed("test0"),
					Addrs: []*netlink.Addr{
						netlinkAddrGlobal(c, "2001::1/64"),
					},
				},
			},
			node: &corev1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: "node",
				},
			},
			nodeIPv6: parseIP(c, "2001::1"),
			wantPatch: &corev1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						IPv4SubnetAnnotationKey: "",
						IPv6SubnetAnnotationKey: "2001::1/64",
					},
				},
			},
		},
		"[happy] applies both subnets on same interface": {
			mockNetworks: []mockNetwork{
				{
					Link: linkNamed("test0"),
					Addrs: []*netlink.Addr{
						netlinkAddrGlobal(c, "192.168.1.1/24"),
						netlinkAddrGlobal(c, "2001::1/64"),
					},
				},
			},
			node: &corev1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: "node",
				},
			},
			nodeIPv4: parseIP(c, "192.168.1.1"),
			nodeIPv6: parseIP(c, "2001::1"),
			wantPatch: &corev1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						IPv4SubnetAnnotationKey: "192.168.1.1/24",
						IPv6SubnetAnnotationKey: "2001::1/64",
					},
				},
			},
		},
		"[happy] applies both subnets on different interfaces": {
			mockNetworks: []mockNetwork{
				{
					Link: linkNamed("test0"),
					Addrs: []*netlink.Addr{
						netlinkAddrGlobal(c, "192.168.1.1/24"),
					},
				},
				{
					Link: linkNamed("test1"),
					Addrs: []*netlink.Addr{
						netlinkAddrGlobal(c, "2001::1/64"),
					},
				},
			},
			node: &corev1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: "node",
				},
			},
			nodeIPv4: parseIP(c, "192.168.1.1"),
			nodeIPv6: parseIP(c, "2001::1"),
			wantPatch: &corev1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						IPv4SubnetAnnotationKey: "192.168.1.1/24",
						IPv6SubnetAnnotationKey: "2001::1/64",
					},
				},
			},
		},
		"[happy] ignores non-global IPv6 address": {
			mockNetworks: []mockNetwork{
				{
					Link: linkNamed("test0"),
					Addrs: []*netlink.Addr{
						netlinkAddrGlobal(c, "192.168.1.1/24"),
						netlinkAddrLocal(c, "fe80::1/64"),
					},
				},
			},
			node: &corev1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: "node",
				},
			},
			nodeIPv4: parseIP(c, "192.168.1.1"),
			nodeIPv6: parseIP(c, "fe80::1"),
			wantPatch: &corev1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						IPv4SubnetAnnotationKey: "192.168.1.1/24",
						IPv6SubnetAnnotationKey: "",
					},
				},
			},
		},
		"[happy] chooses correct subnets from many": {
			mockNetworks: []mockNetwork{
				{
					Link: linkNamed("test0"),
					Addrs: []*netlink.Addr{
						netlinkAddrGlobal(c, "192.168.0.1/24"),
						netlinkAddrGlobal(c, "192.168.1.1/25"),
						netlinkAddrGlobal(c, "192.168.2.1/26"),
						netlinkAddrGlobal(c, "192.168.3.1/27"),
						netlinkAddrGlobal(c, "192.168.4.1/28"),
						netlinkAddrGlobal(c, "2000::1/65"),
						netlinkAddrGlobal(c, "2001::1/66"),
						netlinkAddrGlobal(c, "2002::1/67"),
						netlinkAddrGlobal(c, "2003::1/68"),
						netlinkAddrGlobal(c, "2004::1/69"),
					},
				},
			},
			node: &corev1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: "node",
				},
			},
			nodeIPv4: parseIP(c, "192.168.3.1"),
			nodeIPv6: parseIP(c, "2003::1"),
			wantPatch: &corev1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						IPv4SubnetAnnotationKey: "192.168.3.1/27",
						IPv6SubnetAnnotationKey: "2003::1/68",
					},
				},
			},
		},
		"[happy] chooses correct links from many": {
			mockNetworks: []mockNetwork{
				{
					Link: linkNamed("test0"),
					Addrs: []*netlink.Addr{
						netlinkAddrGlobal(c, "192.168.0.1/24"),
						netlinkAddrGlobal(c, "2000::1/64"),
					},
				},
				{
					Link: linkNamed("test1"),
					Addrs: []*netlink.Addr{
						netlinkAddrGlobal(c, "192.168.1.1/25"),
						netlinkAddrGlobal(c, "2001::1/65"),
					},
				},
				{
					Link: linkNamed("test2"),
					Addrs: []*netlink.Addr{
						netlinkAddrGlobal(c, "192.168.2.1/26"),
						netlinkAddrGlobal(c, "2002::1/66"),
					},
				},
				{
					Link: linkNamed("test3"),
					Addrs: []*netlink.Addr{
						netlinkAddrGlobal(c, "192.168.3.1/27"),
						netlinkAddrGlobal(c, "2003::1/67"),
					},
				},
				{
					Link: linkNamed("test4"),
					Addrs: []*netlink.Addr{
						netlinkAddrGlobal(c, "192.168.4.1/28"),
						netlinkAddrGlobal(c, "2004::1/68"),
					},
				},
			},
			node: &corev1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: "node",
				},
			},
			nodeIPv4: parseIP(c, "192.168.2.1"),
			nodeIPv6: parseIP(c, "2003::1"),
			wantPatch: &corev1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						IPv4SubnetAnnotationKey: "192.168.2.1/26",
						IPv6SubnetAnnotationKey: "2003::1/67",
					},
				},
			},
		},
		"[sad] no match on IPv4 subnet": {
			mockNetworks: []mockNetwork{
				{
					Link: linkNamed("test0"),
					Addrs: []*netlink.Addr{
						netlinkAddrGlobal(c, "192.168.100.1/24"),
						netlinkAddrGlobal(c, "2001::1/64"),
					},
				},
			},
			node: &corev1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: "node",
				},
			},
			nodeIPv4:       parseIP(c, "192.168.1.1"),
			wantErrMatches: "No subnets found",
		},
		"[sad] no match on IPv6 subnet": {
			mockNetworks: []mockNetwork{
				{
					Link: linkNamed("test0"),
					Addrs: []*netlink.Addr{
						netlinkAddrGlobal(c, "192.168.1.1/24"),
						netlinkAddrGlobal(c, "2002::1/64"),
					},
				},
			},
			node: &corev1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: "node",
				},
			},
			nodeIPv6:       parseIP(c, "2001::1"),
			wantErrMatches: "No subnets found",
		},
	}

	for name, test := range tests {
		c.Logf("SUBTEST: %s", name)
		resetNS := applyTestNetNS(c)
		defer resetNS(c)
		applyMockNetworks(c, test.mockNetworks)

		client := &k8sFake.Clientset{}
		nodeName := test.node.Name

		// Other examples use a channel for this but we are testing a function
		// that blocks until the patch is complete. This reactor will run
		// synchronously.
		var patchesRequested int
		client.AddReactor("patch", "nodes", func(action k8sTesting.Action) (handled bool, ret runtime.Object, err error) {
			patchesRequested++

			if test.wantErrMatches != "" {
				c.Errorf("Received patch when we were expecting an error")
				return true, nil, nil
			}

			pa := action.(k8sTesting.PatchAction)
			c.Assert(pa.GetName(), Equals, nodeName, Commentf("Action was not for correct node name"))

			// Check incoming patch.
			bytes := pa.GetPatch()
			gotPatch := &corev1.Node{}
			c.Assert(json.Unmarshal(bytes, &gotPatch), IsNil, Commentf("Could not unmarshal patch"))
			c.Check(gotPatch, DeepEquals, test.wantPatch, Commentf("Patch action did not match expected"))

			return true, nil, nil
		})

		err := annotateNodeSubnets(context.TODO(), client, nodeName, test.nodeIPv4, test.nodeIPv6)
		if test.wantErrMatches != "" {
			c.Assert(err, ErrorMatches, test.wantErrMatches, Commentf("Expected annotateNodeSubnets error to match"))
			c.Assert(patchesRequested, Equals, 0, Commentf("Expected no patches to be applied"))
			continue
		}
		c.Assert(err, IsNil, Commentf("annotateNodeSubnets failed"))
		c.Assert(patchesRequested, Equals, 1, Commentf("Expected one patch to be applied"))
	}
}

func (s *SubnetAnnotationSuite) Test_patchForSubnetAnnotation(c *C) {
	tests := map[string]struct {
		ipv4Subnet     *net.IPNet
		ipv6Subnet     *net.IPNet
		wantPatch      *corev1.Node
		wantErrMatches string
	}{
		"[happy] applies IPv4 subnet": {
			ipv4Subnet: parseIPNet(c, "192.168.1.1/24"),
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
		"[happy] applies IPv6 subnet": {
			ipv4Subnet: nil,
			ipv6Subnet: parseIPNet(c, "2001::1/64"),
			wantPatch: &corev1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						IPv4SubnetAnnotationKey: "",
						IPv6SubnetAnnotationKey: "2001::1/64",
					},
				},
			},
		},
		"[happy] applies both subnets": {
			ipv4Subnet: parseIPNet(c, "192.168.1.1/24"),
			ipv6Subnet: parseIPNet(c, "2001::1/64"),
			wantPatch: &corev1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						IPv4SubnetAnnotationKey: "192.168.1.1/24",
						IPv6SubnetAnnotationKey: "2001::1/64",
					},
				},
			},
		},
		"[happy] wipes both subnets when missing": {
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
		"[sad] subnetIPv4 is wrong family": {
			ipv4Subnet:     parseIPNet(c, "fe80::1/64"),
			ipv6Subnet:     nil,
			wantErrMatches: "ipv4 subnet is incorrect family.*",
		},
		"[sad] subnetIPv6 is wrong family": {
			ipv4Subnet:     nil,
			ipv6Subnet:     parseIPNet(c, "192.168.1.1/24"),
			wantErrMatches: "ipv6 subnet is incorrect family.*",
		},
	}

	for name, test := range tests {
		c.Logf("SUBTEST: %s", name)
		patchBytes, err := patchForSubnetAnnotations(test.ipv4Subnet, test.ipv6Subnet)
		if test.wantErrMatches != "" {
			c.Assert(err, ErrorMatches, test.wantErrMatches, Commentf("Expected patchForSubnetAnnotations error to match"))
			continue
		}
		c.Assert(err, IsNil, Commentf("patchForSubnetAnnotations failed"))

		gotPatch := &corev1.Node{}
		c.Assert(json.Unmarshal(patchBytes, &gotPatch), IsNil, Commentf("Could not unmarshal patch"))
		c.Check(gotPatch, DeepEquals, test.wantPatch, Commentf("Patch did not match expected: patchBytes: %q", string(patchBytes)))
	}
}

func (s *SubnetAnnotationSuite) Test_subnetFor(c *C) {
	tests := map[string]struct {
		mockNetworks   []mockNetwork
		ip             net.IP
		wantSubnet     *net.IPNet
		wantErrMatches string
	}{
		"[happy] finds link and address associated with IPv4 address": {
			mockNetworks: []mockNetwork{
				{
					Link: linkNamed("test0"),
					Addrs: []*netlink.Addr{
						netlinkAddrGlobal(c, "192.168.1.1/24"),
						netlinkAddrGlobal(c, "192.168.1.2/24"),
						netlinkAddrGlobal(c, "2001::1/64"),
						netlinkAddrGlobal(c, "2001::2/64"),
					},
				},
			},
			ip:         parseIP(c, "192.168.1.1"),
			wantSubnet: parseIPNet(c, "192.168.1.1/24"),
		},
		"[happy] finds link and address associated with IPv6 address": {
			mockNetworks: []mockNetwork{
				{
					Link: linkNamed("test0"),
					Addrs: []*netlink.Addr{
						netlinkAddrGlobal(c, "192.168.1.1/24"),
						netlinkAddrGlobal(c, "192.168.1.2/24"),
						netlinkAddrGlobal(c, "2001::1/64"),
						netlinkAddrGlobal(c, "2001::2/64"),
					},
				},
			},
			ip:         parseIP(c, "2001::1"),
			wantSubnet: parseIPNet(c, "2001::1/64"),
		},
		"[happy] finds correct link out of many": {
			mockNetworks: []mockNetwork{
				{
					Link: linkNamed("test0"),
					Addrs: []*netlink.Addr{
						netlinkAddrGlobal(c, "192.168.0.1/24"),
						netlinkAddrGlobal(c, "192.168.0.2/24"),
					},
				},
				{
					Link: linkNamed("test1"),
					Addrs: []*netlink.Addr{
						netlinkAddrGlobal(c, "192.168.1.1/24"),
						netlinkAddrGlobal(c, "192.168.1.2/24"),
					},
				},
				{
					Link: linkNamed("test2"),
					Addrs: []*netlink.Addr{
						netlinkAddrGlobal(c, "192.168.2.1/24"),
						netlinkAddrGlobal(c, "192.168.2.2/24"),
					},
				},
				{
					Link: linkNamed("test3"),
					Addrs: []*netlink.Addr{
						netlinkAddrGlobal(c, "192.168.3.1/24"),
						netlinkAddrGlobal(c, "192.168.3.2/24"),
					},
				},
			},
			ip:         parseIP(c, "192.168.2.1"),
			wantSubnet: parseIPNet(c, "192.168.2.1/24"),
		},
		"[happy] returns nil for nil IP": {
			ip:         nil,
			wantSubnet: nil,
		},
		"[sad] gives err when IP matches addr with non-global scope": {
			mockNetworks: []mockNetwork{
				{
					Link: linkNamed("test0"),
					Addrs: []*netlink.Addr{
						netlinkAddrLocal(c, "fe80::1/64"),
					},
				},
			},
			ip:             parseIP(c, "fe80::1"),
			wantErrMatches: "found address for IP but it is not universal scope.*",
		},
		"[sad] gives err when IP is not found on any interfaces": {
			mockNetworks: []mockNetwork{
				{
					Link: linkNamed("test0"),
					Addrs: []*netlink.Addr{
						netlinkAddrGlobal(c, "192.168.1.2/24"),
					},
				},
			},
			ip:             parseIP(c, "192.168.1.1"),
			wantErrMatches: "failed to find link.*",
		},
	}
	for name, test := range tests {
		c.Logf("SUBTEST: %s", name)
		resetNS := applyTestNetNS(c)
		defer resetNS(c)
		applyMockNetworks(c, test.mockNetworks)

		gotSubnet, err := subnetFor(test.ip)
		if test.wantErrMatches != "" {
			c.Assert(err, ErrorMatches, test.wantErrMatches, Commentf("Expected subnetFor error to match"))
			continue
		}
		c.Assert(err, IsNil, Commentf("subnetFor failed"))

		ignoreLabel := cmpopts.IgnoreFields(netlink.Addr{}, "Label")
		if diff := cmp.Diff(gotSubnet, test.wantSubnet, ignoreLabel); diff != "" {
			c.Errorf("Matching subnet differed from expected (-got, +want):\n%s", name, diff)
		}
	}
}

// applyTestNetNS applies a new test namespace and returns a function that can
// be deferred to reset the namespace back to its original state.
func applyTestNetNS(c *C) (resetNS func(c *C)) {
	currNetNS, err := netns.Get()
	c.Assert(err, IsNil, Commentf("TEST BUG: Failed to get current network namespace"))
	testNetNS, err := netns.New()
	c.Assert(err, IsNil, Commentf("TEST BUG: Failed to create test network namespace"))
	return func(c *C) {
		defer func() {
			c.Assert(testNetNS.Close(), IsNil, Commentf("TEST BUG: Failed to close test network namespace"))
		}()
		defer func() {
			c.Assert(netns.Set(currNetNS), IsNil, Commentf("TEST BUG: Failed to change to previous network namespace"))
		}()
	}
}

// applyMockNetworks applies mockNetworks to the current network namespace.
func applyMockNetworks(c *C, mockNetworks []mockNetwork) {
	for _, mock := range mockNetworks {
		linkName := mock.Link.Attrs().Name
		c.Assert(netlink.LinkAdd(mock.Link), IsNil, Commentf("TEST BUG: failed to add placeholder link %q", linkName))
		link, err := netlink.LinkByName(linkName)
		c.Assert(err, IsNil, Commentf("TEST BUG: failed to get placeholder link %q", linkName))
		for _, addr := range mock.Addrs {
			c.Assert(netlink.AddrAdd(link, addr), IsNil, Commentf("TEST BUG: failed to add address %q to placeholder link %s", addr, linkName))
		}
	}
}

// parseIP converts an ip string to net.IP.
func parseIP(c *C, ipStr string) net.IP {
	ip := net.ParseIP(ipStr)
	c.Assert(ip, Not(IsNil), Commentf("TEST BUG: failed to parse IP %q", ipStr))
	return ip
}

// parseIP converts a CIDR string to net.IPNet.
func parseIPNet(c *C, cidr string) *net.IPNet {
	ip, net, err := net.ParseCIDR(cidr)
	c.Assert(err, IsNil, Commentf("TEST BUG: failed to parse CIDR %q", cidr))
	net.IP = ip
	return net
}

func netlinkAddrGlobal(c *C, cidr string) *netlink.Addr {
	return &netlink.Addr{
		IPNet: parseIPNet(c, cidr),
		Scope: unix.RT_SCOPE_UNIVERSE,
	}
}

func netlinkAddrLocal(c *C, cidr string) *netlink.Addr {
	return &netlink.Addr{
		IPNet: parseIPNet(c, cidr),
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
