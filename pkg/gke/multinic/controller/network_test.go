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

package controller

import (
	"context"
	"net"
	"runtime"
	"testing"
	"time"

	networkv1 "github.com/GoogleCloudPlatform/gke-networking-api/apis/network/v1"
	agentK8s "github.com/cilium/cilium/daemon/k8s"
	"github.com/cilium/cilium/pkg/endpoint"
	multinicclients "github.com/cilium/cilium/pkg/gke/multinic/clients"
	"github.com/cilium/cilium/pkg/gke/multinic/multinicconfig"
	"github.com/cilium/cilium/pkg/hive"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maps/multinet"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/testutils"
	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/google/go-cmp/cmp"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	utilpointer "k8s.io/utils/pointer"

	anutils "gke-internal.googlesource.com/anthos-networking/apis/v2/utils"

	"github.com/cilium/cilium/pkg/ipam"
)

const (
	networkName    = "my-network"
	testNamespace  = "test-namespace"
	vlanID100      = 100
	nodeName       = "test-node"
	parentLinkName = "foo"
)

var log = logging.DefaultLogger.WithField(logfields.LogSubsys, "test")

type testIPAMMgr struct{}

func (t testIPAMMgr) UpdateMultiNetworkIPAMAllocators(annotations map[string]string) error {
	_, ok := annotations[networkv1.MultiNetworkAnnotationKey]
	if !ok {
		return nil
	}
	node.SetAnnotations(annotations)
	return nil
}

func (t testIPAMMgr) ReserveGatewayIP(network *networkv1.Network) error {
	return nil
}

func (t testIPAMMgr) PreAllocateIPsForRestoredMultiNICEndpoints(eps []*endpoint.Endpoint) error {
	return nil
}

func (t testIPAMMgr) GetMultiNetworkIPAMAllocators() map[string]ipam.Allocator {
	return nil
}

func TestEnsureInterface(t *testing.T) {
	testutils.PrivilegedTest(t)

	cr := &networkv1.Network{
		ObjectMeta: metav1.ObjectMeta{
			Name:      networkName,
			Namespace: testNamespace,
		},
		Spec: networkv1.NetworkSpec{
			NodeInterfaceMatcher: networkv1.NodeInterfaceMatcher{
				InterfaceName: utilpointer.String(parentLinkName),
			},
			L2NetworkConfig: &networkv1.L2NetworkConfig{
				VlanID: utilpointer.Int32(100),
			},
		},
	}

	noVlanIDCR := cr.DeepCopy()
	noVlanIDCR.Spec.L2NetworkConfig.VlanID = nil

	userManaged := networkv1.UserManagedLifecycle
	userManagedCR := cr.DeepCopy()
	userManagedCR.Spec.NetworkLifecycle = &userManaged

	expectedIntName := "foo.100"

	testcases := []struct {
		desc      string
		networkCR *networkv1.Network
		// Specify whether the tagged interface exists before ensureInterface
		intExists bool
		// Specify whether a tagged interface should exist after ensureInterface
		expectTag bool
		// Specify whether the parent interface is down before ensureInterface
		parentIntfDown bool
	}{
		{
			desc:      "network exists, and vlan id is not specified",
			networkCR: noVlanIDCR,
			expectTag: false,
		},
		{
			desc:      "network exists, and vlan id is specified",
			networkCR: cr,
			expectTag: true,
		},
		{
			desc:      "network exists, and vlan tag already exists",
			networkCR: cr,
			intExists: true,
			expectTag: true,
		},
		{
			desc:      "network exists, and vlan id is specified, and userMangaged",
			networkCR: userManagedCR,
			expectTag: false,
		},
		{
			desc:           "parent interface is down",
			networkCR:      cr,
			expectTag:      true,
			parentIntfDown: false,
		},
	}

	for _, tc := range testcases {
		testFunc := func() {
			defer cleanupLinks(t, expectedIntName, parentLinkName)

			parentLink := setupParentLink(t, parentLinkName)

			if tc.intExists {
				vlan := netlink.Vlan{
					LinkAttrs: netlink.LinkAttrs{
						Name:        expectedIntName,
						ParentIndex: parentLink.Attrs().Index,
					},
					VlanId: vlanID100,
				}
				err := netlink.LinkAdd(&vlan)
				if err != nil {
					t.Fatalf("failed creating tagged interface: %s", err)
				}
			}

			if tc.parentIntfDown {
				if err := netlink.LinkSetDown(parentLink); err != nil {
					t.Fatal("failed bringing down the parent interface")
				}
				if !waitForLinkStateChange(t, parentLinkName, netlink.OperDown) {
					t.Fatal("the parent link is not down after waiting")
				}
			}

			intfName, _, err := anutils.InterfaceInfo(tc.networkCR, map[string]string{})
			if err != nil {
				t.Fatalf("InterfaceInfo returned an unexpected error: %s", err)
			}
			err = ensureInterface(tc.networkCR, intfName, log)
			if err != nil {
				t.Fatalf("ensureVlanID returned an unexpected error: %s", err)
			}

			var link netlink.Link
			link, err = netlink.LinkByName(expectedIntName)
			if !tc.expectTag {
				if err == nil {
					t.Fatalf("expected link %s not to exist", expectedIntName)
				}
				return
			}
			if err != nil {
				t.Fatalf("failed to find tagged interface %s: %s", expectedIntName, err)
			}
			if !waitForLinkStateChange(t, expectedIntName, netlink.OperUp) {
				t.Fatalf("the tagged interface is not up: %s", link.Attrs().OperState)
			}
			// The parent link doesn't have lower layer access so the operation state
			// is UNKNOWN.
			if !waitForLinkStateChange(t, parentLinkName, netlink.OperUnknown) {
				t.Fatalf("the parent interface is not up: %s", parentLink.Attrs().OperState)
			}

			vlan, ok := link.(*netlink.Vlan)
			if !ok {
				t.Fatalf("link %s, is a vlan interface", expectedIntName)
			}

			if vlan.VlanId != vlanID100 {
				t.Fatalf("got vlan id %d, but wanted %d", vlan.VlanId, vlanID100)
			}
		}
		t.Run(tc.desc, func(t *testing.T) { runTestInNetNS(t, testFunc) })
	}
}

func TestEnsureInterfaceErrors(t *testing.T) {
	testutils.PrivilegedTest(t)

	cr := &networkv1.Network{
		ObjectMeta: metav1.ObjectMeta{
			Name:      networkName,
			Namespace: testNamespace,
		},
		Spec: networkv1.NetworkSpec{
			NodeInterfaceMatcher: networkv1.NodeInterfaceMatcher{
				InterfaceName: utilpointer.String(parentLinkName),
			},
			L2NetworkConfig: &networkv1.L2NetworkConfig{
				VlanID: utilpointer.Int32(100),
			},
		},
	}

	expectedIntName := "foo.100"

	type vlanDef struct {
		parentInterface string
		vlanID          int
	}

	testcases := []struct {
		desc         string
		networkCR    *networkv1.Network
		existingVlan *vlanDef
	}{
		{
			desc:      "network exists, and vlan tag is specified, parent int doesn't exist",
			networkCR: cr,
		},
		{
			desc:      "network exists, tagged interface exists with incorrect tag",
			networkCR: cr,
			existingVlan: &vlanDef{
				parentInterface: parentLinkName,
				vlanID:          101,
			},
		},
		{
			desc:      "network exists, tagged interface exists with incorrect parent interface",
			networkCR: cr,
			existingVlan: &vlanDef{
				parentInterface: "foo1",
				vlanID:          100,
			},
		},
	}

	for _, tc := range testcases {
		testFunc := func() {

			if tc.existingVlan != nil {
				defer cleanupLinks(t, expectedIntName, parentLinkName, "foo1")
				setupParentLink(t, parentLinkName)
				setupParentLink(t, "foo1")

				parentLink, err := netlink.LinkByName(tc.existingVlan.parentInterface)
				if err != nil {
					t.Fatalf("failed to setup parent interface %s: %s", tc.existingVlan.parentInterface, err)
				}
				vlan := netlink.Vlan{
					LinkAttrs: netlink.LinkAttrs{
						Name:        expectedIntName,
						ParentIndex: parentLink.Attrs().Index,
					},
					VlanId: tc.existingVlan.vlanID,
				}
				err = netlink.LinkAdd(&vlan)
				if err != nil {
					t.Fatalf("failed creating tagged interface: %s", err)
				}
			}

			intfName, _, err := anutils.InterfaceInfo(tc.networkCR, map[string]string{})
			if err != nil {
				t.Fatalf("InterfaceInfo returned an unexpected error: %s", err)
			}
			err = ensureInterface(tc.networkCR, intfName, log)
			if err == nil {
				t.Fatal("ensureVlanID returns nil but want error")
			}
		}
		t.Run(tc.desc, func(t *testing.T) { runTestInNetNS(t, testFunc) })
	}
}

func TestDeleteVlanID(t *testing.T) {
	testutils.PrivilegedTest(t)

	cr := &networkv1.Network{
		ObjectMeta: metav1.ObjectMeta{
			Name:      networkName,
			Namespace: testNamespace,
		},
		Spec: networkv1.NetworkSpec{
			NodeInterfaceMatcher: networkv1.NodeInterfaceMatcher{
				InterfaceName: utilpointer.String(parentLinkName),
			},
			L2NetworkConfig: &networkv1.L2NetworkConfig{
				VlanID: utilpointer.Int32(100),
			},
		},
	}

	userManaged := networkv1.UserManagedLifecycle
	userManagedCR := cr.DeepCopy()
	userManagedCR.Spec.NetworkLifecycle = &userManaged

	noVlanCR := cr.DeepCopy()
	noVlanCR.Spec.L2NetworkConfig = nil

	expectedIntName := "foo.100"

	testcases := []struct {
		desc      string
		networkCR *networkv1.Network
		// Specify whether the tagged interface was already deleted
		intAlreadyDeleted bool
		// Specify whether a tagged interface should be deleted
		expectDeletion bool
	}{
		{
			desc:           "network cr is deleted, and in-use annotation does not exist",
			networkCR:      cr,
			expectDeletion: true,
		},
		{
			desc:              "network cr is deleted, and in-use annotation does not exist, vlan already deleted",
			networkCR:         cr,
			intAlreadyDeleted: true,
			expectDeletion:    true,
		},
		{
			desc:           "network cr is userMangaged",
			networkCR:      userManagedCR,
			expectDeletion: false,
		},
		{

			desc:           "network does not have l2networkconfig",
			networkCR:      noVlanCR,
			expectDeletion: false,
		},
	}

	for _, tc := range testcases {
		testFunc := func() {
			defer cleanupLinks(t, expectedIntName, parentLinkName)

			parentLink := setupParentLink(t, parentLinkName)

			if !tc.intAlreadyDeleted {
				vlan := netlink.Vlan{
					LinkAttrs: netlink.LinkAttrs{
						Name:        expectedIntName,
						ParentIndex: parentLink.Attrs().Index,
					},
					VlanId: vlanID100,
				}
				err := netlink.LinkAdd(&vlan)
				if err != nil {
					t.Fatalf("failed creating tagged interface: %s", err)
				}
			}
			err := deleteVlanID(tc.networkCR, &slim_corev1.Node{}, log)
			if err != nil {
				t.Fatalf("encountered unexpected err: %s", err)
			}

			_, err = netlink.LinkByName(expectedIntName)
			if tc.expectDeletion {
				if err == nil {
					t.Fatalf("expected link %s not to exist", expectedIntName)
				}
				return
			}
			if err != nil {
				t.Fatalf("expected link to not be deleted, failed to find tagged interface %s: %s", expectedIntName, err)
			}
		}
		t.Run(tc.desc, func(t *testing.T) { runTestInNetNS(t, testFunc) })
	}
}

func waitForLinkStateChange(t *testing.T, name string, expectedState netlink.LinkOperState) bool {
	for i := 0; i < 10; i++ {
		link, err := netlink.LinkByName(name)
		if err != nil {
			t.Fatalf("unable to check link state as link is not found: %s", name)
		}
		if link.Attrs().OperState == expectedState {
			return true
		}
		// Add sleep time for the link's operational state to change.
		time.Sleep(500 * time.Millisecond)
	}
	return false
}

func runTestInNetNS(t *testing.T, test func()) {
	// Source:
	// https://github.com/vishvananda/netlink/blob/c79a4b7b40668c3f7867bf256b80b6b2dc65e58e/netns_test.go#L49
	runtime.LockOSThread() // We need a constant OS thread
	defer runtime.UnlockOSThread()

	currentNS, err := netns.Get()
	if err != nil {
		t.Fatalf("failed to get current networking namespace: %s", err)
	}
	defer netns.Set(currentNS)
	networkNS, err := netns.New()
	if err != nil {
		t.Fatalf("failed to create test network namespace: %s", err)
	}
	defer networkNS.Close()

	test()
}

// setup a dummy link with the provided parentName
func setupParentLink(t *testing.T, parentName string) netlink.Link {
	return setupParentLinkWithAttrs(t, netlink.LinkAttrs{Name: parentName})
}

func setupParentLinkWithAttrs(t *testing.T, attrs netlink.LinkAttrs) netlink.Link {
	parent := &netlink.Dummy{LinkAttrs: attrs}
	err := netlink.LinkAdd(parent)
	if err != nil {
		t.Fatalf("unable to add parent interface: %s", err)
	}
	err = netlink.LinkSetUp(parent)
	if err != nil {
		t.Fatalf("unable to bring up parent interface: %s", err)
	}
	return parent
}

// cleanupLinks ensures that the provided links do not exist or will delete if they do exist
func cleanupLinks(t *testing.T, linkNames ...string) {
	for _, name := range linkNames {
		link, err := netlink.LinkByName(name)
		if err == nil {
			netlink.LinkDel(link)
		}
	}
}

func TestUpdateNodeNetworkStatusAnnotation(t *testing.T) {
	ctx := context.Background()
	var networks resource.Resource[*networkv1.Network]
	var fakeClient k8sClient.FakeClientset
	hive := hive.New(
		cell.Provide(func() multinicconfig.Config {
			return multinicconfig.Config{
				EnableGoogleMultiNIC: true,
			}
		}),
		k8sClient.FakeClientCell,
		multinicclients.FakeMNClientCell,
		agentK8s.ResourcesCell,
		cell.Invoke(func(
			c *k8sClient.FakeClientset,
			nws resource.Resource[*networkv1.Network],
			ln agentK8s.LocalNodeResource,
		) error {
			fakeClient = *c
			networks = nws
			return nil
		}),
	)
	tlog := hivetest.Logger(t)
	hive.Start(tlog, context.Background())
	testcases := []struct {
		desc                string
		existingAnnotations map[string]string
		nodeName            string
		network             string
		ipv4Subnet          string
		ipv6Subnet          string
		isAdd               bool
		wantErr             string
		wantPatchErr        string
		wantAnnotations     map[string]string
	}{
		{
			desc: "add new network to existing annotation",
			existingAnnotations: map[string]string{
				networkv1.NodeNetworkAnnotationKey: `[{"name":"foo"}]`,
			},
			nodeName: nodeName,
			network:  "bar",
			isAdd:    true,
			wantAnnotations: map[string]string{
				networkv1.NodeNetworkAnnotationKey: `[{"name":"bar"},{"name":"foo"}]`,
			},
		},
		{
			desc:                "add new node network annotation",
			existingAnnotations: map[string]string{},
			nodeName:            nodeName,
			network:             "bar",
			isAdd:               true,
			wantAnnotations: map[string]string{
				networkv1.NodeNetworkAnnotationKey: `[{"name":"bar"}]`,
			},
		},
		{
			desc:                "add new node network annotation to nil existing annotation",
			existingAnnotations: nil,
			nodeName:            nodeName,
			network:             "bar",
			isAdd:               true,
			wantAnnotations: map[string]string{
				networkv1.NodeNetworkAnnotationKey: `[{"name":"bar"}]`,
			},
		},
		{
			desc: "add new network to null annotation value",
			existingAnnotations: map[string]string{
				networkv1.NodeNetworkAnnotationKey: "null",
			},
			nodeName: nodeName,
			network:  "bar",
			isAdd:    true,
			wantAnnotations: map[string]string{
				networkv1.NodeNetworkAnnotationKey: `[{"name":"bar"}]`,
			},
		},
		{
			desc: "add new network to empty annotation value",
			existingAnnotations: map[string]string{
				networkv1.NodeNetworkAnnotationKey: "",
			},
			nodeName: nodeName,
			network:  "bar",
			isAdd:    true,
			wantAnnotations: map[string]string{
				networkv1.NodeNetworkAnnotationKey: `[{"name":"bar"}]`,
			},
		},
		{
			desc:                "add new network with ipv4 subnet",
			existingAnnotations: map[string]string{},
			nodeName:            nodeName,
			network:             "bar",
			ipv4Subnet:          "10.0.0.1/21",
			isAdd:               true,
			wantAnnotations: map[string]string{
				networkv1.NodeNetworkAnnotationKey: `[{"name":"bar","ipv4-subnet":"10.0.0.1/21"}]`,
			},
		},
		{
			desc:                "add new network with ipv4/v6 subnets",
			existingAnnotations: map[string]string{},
			nodeName:            nodeName,
			network:             "bar",
			ipv4Subnet:          "10.0.0.1/21",
			ipv6Subnet:          "2001:db8:a0b:12f0::1/64",
			isAdd:               true,
			wantAnnotations: map[string]string{
				networkv1.NodeNetworkAnnotationKey: `[{"name":"bar","ipv4-subnet":"10.0.0.1/21","ipv6-subnet":"2001:db8:a0b:12f0::1/64"}]`,
			},
		},
		{
			desc: "add subnets to existing network",
			existingAnnotations: map[string]string{
				networkv1.NodeNetworkAnnotationKey: `[{"name":"bar"}]`,
			},
			nodeName:   nodeName,
			network:    "bar",
			ipv4Subnet: "10.0.0.1/21",
			ipv6Subnet: "2001:db8:a0b:12f0::1/64",
			isAdd:      true,
			wantAnnotations: map[string]string{
				networkv1.NodeNetworkAnnotationKey: `[{"name":"bar","ipv4-subnet":"10.0.0.1/21","ipv6-subnet":"2001:db8:a0b:12f0::1/64"}]`,
			},
		},
		{
			desc: "add existing network",
			existingAnnotations: map[string]string{
				networkv1.NodeNetworkAnnotationKey: `[{"name":"foo"}]`,
			},
			nodeName: nodeName,
			network:  parentLinkName,
			isAdd:    true,
			wantAnnotations: map[string]string{
				networkv1.NodeNetworkAnnotationKey: `[{"name":"foo"}]`,
			},
		},
		{
			desc: "delete last network in existing annotation",
			existingAnnotations: map[string]string{
				networkv1.NodeNetworkAnnotationKey: `[{"name":"foo"}]`,
			},
			nodeName: nodeName,
			network:  parentLinkName,
			isAdd:    false,
			wantAnnotations: map[string]string{
				networkv1.NodeNetworkAnnotationKey: "[]",
			},
		},
		{
			desc: "delete network in existing annotation",
			existingAnnotations: map[string]string{
				networkv1.NodeNetworkAnnotationKey: `[{"name":"foo"},{"name":"bar"}]`,
			},
			nodeName: nodeName,
			network:  "bar",
			isAdd:    false,
			wantAnnotations: map[string]string{
				networkv1.NodeNetworkAnnotationKey: `[{"name":"foo"}]`,
			},
		},
		{
			desc: "delete network not in existing annotation",
			existingAnnotations: map[string]string{
				networkv1.NodeNetworkAnnotationKey: `[{"name":"foo"}]`,
			},
			nodeName: nodeName,
			network:  "bar",
			isAdd:    false,
			wantAnnotations: map[string]string{
				networkv1.NodeNetworkAnnotationKey: `[{"name":"foo"}]`,
			},
		},
		{
			desc: "node network annotation parse failure",
			existingAnnotations: map[string]string{
				networkv1.NodeNetworkAnnotationKey: `invalid_annotation`,
			},
			nodeName: nodeName,
			wantErr:  "failed to get network status map from node \"test-node\": invalid character 'i' looking for beginning of value",
		},
		{
			desc: "not found node",
			existingAnnotations: map[string]string{
				networkv1.NodeNetworkAnnotationKey: `[{"name":"foo"}]`,
			},
			nodeName:     "foo-node",
			network:      parentLinkName,
			wantPatchErr: "failed to patch k8s node \"foo-node\": nodes \"foo-node\" not found",
		},
	}
	for _, tc := range testcases {
		t.Run(tc.desc, func(t *testing.T) {
			testNode := &corev1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name:        nodeName,
					Annotations: tc.existingAnnotations,
				},
			}
			fakeClient.CoreV1().Nodes().Create(context.TODO(), testNode, metav1.CreateOptions{})
			slimTestNode := &slim_corev1.Node{
				ObjectMeta: v1.ObjectMeta{
					Name:        nodeName,
					Annotations: tc.existingAnnotations,
				},
			}

			testNode.Name = tc.nodeName
			testReconciler := NetworkReconciler{
				Clientset: &fakeClient,
				Networks:  networks,
				NodeName:  tc.nodeName,
				IPAMMgr:   testIPAMMgr{},
				Log:       logging.DefaultLogger.WithField(logfields.LogSubsys, "test"),
			}
			slimTestNode.Name = tc.nodeName
			oldNode := slimTestNode.DeepCopy()
			testReconciler.lastNode = slimTestNode
			gotErr := updateNodeNetworkStatusAnnotation(ctx, slimTestNode, tc.network, tc.ipv4Subnet, tc.ipv6Subnet, logger, tc.isAdd)
			if gotErr != nil {
				if tc.wantErr == "" {
					t.Fatalf("updateNodeNetworkStatusAnnotation() return error %v but want nil", gotErr)
				}
				if gotErr.Error() != tc.wantErr {
					t.Fatalf("updateNodeNetworkStatusAnnotation() return error %v but want %v", gotErr, tc.wantErr)
				}
				return
			}

			patchErr := testReconciler.patchNodeAnnotations(ctx, oldNode, slimTestNode)
			if patchErr != nil {
				if tc.wantPatchErr == "" {
					t.Fatalf("patchNodeAnnotations() return error %v but want nil", patchErr)
				}
				if patchErr.Error() != tc.wantPatchErr {
					t.Fatalf("patchNodeAnnotations() return error %v but want %v", patchErr, tc.wantPatchErr)
				}
				return
			}
			gotNode, err := fakeClient.CoreV1().Nodes().Get(ctx, tc.nodeName, metav1.GetOptions{})
			if err != nil {
				t.Fatalf("failed to get k8s node: %v", err)
			}

			if diff := cmp.Diff(gotNode.Annotations, tc.wantAnnotations); diff != "" {
				t.Fatalf("updateNodeNetworkAnnotation() return unexpected output (-got, +want):\n%s", diff)
			}

			fakeClient.CoreV1().Nodes().Delete(ctx, testNode.Name, metav1.DeleteOptions{})
		})
	}
}

func ipNetUnsafe(ipStr string) *net.IPNet {
	ip, netIP, _ := net.ParseCIDR(ipStr)
	netIP.IP = ip
	return netIP
}

func TestBestAddrMatch(t *testing.T) {
	testcases := []struct {
		desc     string
		addrs    []netlink.Addr
		wantAddr *net.IPNet
	}{
		{
			desc:     "with one IP",
			addrs:    []netlink.Addr{{IPNet: ipNetUnsafe("10.0.0.1/28"), Scope: int(netlink.SCOPE_UNIVERSE)}},
			wantAddr: ipNetUnsafe("10.0.0.1/28"),
		},
		{
			desc: "with multiple IPs and subnet sizes",
			addrs: []netlink.Addr{
				{IPNet: ipNetUnsafe("10.0.0.1/28"), Scope: int(netlink.SCOPE_UNIVERSE)},
				{IPNet: ipNetUnsafe("10.0.0.2/27"), Scope: int(netlink.SCOPE_UNIVERSE)},
				{IPNet: ipNetUnsafe("10.0.0.3/24"), Scope: int(netlink.SCOPE_UNIVERSE)},
				{IPNet: ipNetUnsafe("10.0.0.4/26"), Scope: int(netlink.SCOPE_UNIVERSE)},
			},
			wantAddr: ipNetUnsafe("10.0.0.3/24"),
		},
		{
			desc: "with different scopes",
			addrs: []netlink.Addr{
				{IPNet: ipNetUnsafe("10.0.0.1/16"), Scope: int(netlink.SCOPE_NOWHERE)},
				{IPNet: ipNetUnsafe("10.0.0.2/24"), Scope: int(netlink.SCOPE_LINK)},
				{IPNet: ipNetUnsafe("10.0.0.3/26"), Scope: int(netlink.SCOPE_HOST)},
				{IPNet: ipNetUnsafe("10.0.0.4/28"), Scope: int(netlink.SCOPE_UNIVERSE)},
			},
			wantAddr: ipNetUnsafe("10.0.0.4/28"),
		},
		{
			desc:     "with no IPs",
			addrs:    []netlink.Addr{},
			wantAddr: nil,
		},
		{
			desc: "with no valid IP",
			addrs: []netlink.Addr{
				{IPNet: ipNetUnsafe("10.0.0.1/28"), Scope: int(netlink.SCOPE_NOWHERE)},
				{IPNet: ipNetUnsafe("10.0.0.2/28"), Scope: int(netlink.SCOPE_LINK)},
				{IPNet: ipNetUnsafe("10.0.0.3/28"), Scope: int(netlink.SCOPE_HOST)},
			},
			wantAddr: nil,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.desc, func(t *testing.T) {
			got := bestAddrMatch(tc.addrs)
			if got == nil {
				if tc.wantAddr != nil {
					t.Fatalf("Didn't get correct IP net, got nil when %s was expected", tc.wantAddr.String())
				}
				return
			}
			if got.IP.String() != tc.wantAddr.IP.String() {
				t.Fatalf("Didn't get the correct IP, got: %s, wanted: %s", got.IP.String(), tc.wantAddr.IP.String())
			}
			if got.Mask.String() != tc.wantAddr.Mask.String() {
				t.Fatalf("Didn't get the correct IP Mask, got: %s, wanted: %s", got.Mask.String(), tc.wantAddr.Mask.String())
			}
		})
	}
}

func TestUpdateNodeMultiNetworkIPAM(t *testing.T) {
	ctx := context.Background()
	var networks resource.Resource[*networkv1.Network]
	var fakeClient k8sClient.FakeClientset
	var localNodeResource agentK8s.LocalNodeResource
	hive := hive.New(
		cell.Provide(func() multinicconfig.Config {
			return multinicconfig.Config{
				EnableGoogleMultiNIC: true,
			}
		}),
		k8sClient.FakeClientCell,
		multinicclients.FakeMNClientCell,
		agentK8s.ResourcesCell,
		cell.Invoke(func(
			c *k8sClient.FakeClientset,
			nws resource.Resource[*networkv1.Network],
			ln agentK8s.LocalNodeResource,
		) error {
			fakeClient = *c
			networks = nws
			localNodeResource = ln
			return nil
		}),
	)
	tlog := hivetest.Logger(t)
	hive.Start(tlog, ctx)
	nodeStore, _ := localNodeResource.Store(ctx)
	testReconciler := NetworkReconciler{
		Clientset:         &fakeClient,
		Networks:          networks,
		IPAMMgr:           testIPAMMgr{},
		Log:               log,
		LocalNodeResource: localNodeResource,
		NodeName:          nodeName,
	}
	testNw := networkv1.Network{ObjectMeta: metav1.ObjectMeta{Name: networkName}, Spec: networkv1.NetworkSpec{Type: networkv1.L2NetworkType}}
	testcases := []struct {
		desc                string
		existingAnnotations map[string]string
		nodeName            string
		wantErr             string
		network             *networkv1.Network
	}{
		{
			desc: "node not found",
			existingAnnotations: map[string]string{
				networkv1.MultiNetworkAnnotationKey: `[{"name":"foo", "cidrs":["10.0.0.0/21"],"scope":"host-local"}]`,
			},
			nodeName: "foo-node",
			wantErr:  "failed to fetch latest local node while updating multinetworking IPAM: local node foo-node not found",
			network:  &testNw,
		},
		{
			desc: "single network IPAM - add",
			existingAnnotations: map[string]string{
				networkv1.MultiNetworkAnnotationKey: `[{"name":"my-network", "cidrs":["10.0.0.0/21"],"scope":"host-local"}]`,
			},
			nodeName: nodeName,
			network:  &testNw,
		},
		{
			desc: "multi network IPAM - add",
			existingAnnotations: map[string]string{
				networkv1.MultiNetworkAnnotationKey: `[{"name":"my-network", "cidrs":["10.0.0.0/21"],"scope":"host-local"}, {"name":"bar", "cidrs":["20.0.0.0/21"],"scope":"host-local"}]`,
			},
			nodeName: nodeName,
			network:  &testNw,
		},
		{
			desc:     "externalDHCP enabled network - no IPAM",
			nodeName: nodeName,
			network:  &networkv1.Network{ObjectMeta: metav1.ObjectMeta{Name: networkName}, Spec: networkv1.NetworkSpec{Type: networkv1.L2NetworkType, ExternalDHCP4: utilpointer.Bool(true)}},
		},
	}
	for _, tc := range testcases {
		t.Run(tc.desc, func(t *testing.T) {
			node.SetAnnotations(nil)
			slimTestNode := &slim_corev1.Node{
				ObjectMeta: v1.ObjectMeta{
					Name:        nodeName,
					Annotations: tc.existingAnnotations,
				},
			}
			nodeStore.CacheStore().Add(slimTestNode)
			gotErr := testReconciler.updateMultiNetworkIPAM(ctx, tc.network)
			if gotErr != nil {
				if tc.wantErr == "" {
					t.Fatalf("updateMultiNetworkIPAM() returns error %v but want nil", gotErr)
				}
				if gotErr.Error() != tc.wantErr {
					t.Fatalf("updateMultiNetworkIPAM() returns error %v but want %v", gotErr, tc.wantErr)
				}
				return
			}
			gotAnnotations := node.GetAnnotations()
			if diff := cmp.Diff(gotAnnotations, tc.existingAnnotations); diff != "" {
				t.Fatalf("updateMultiNetworkIPAM() returns unexpected output (-got, +want):\n%s", diff)
			}
		})
	}
}

func TestUpdateHostDeviceRouting(t *testing.T) {
	testutils.PrivilegedTest(t)
	ctx := context.Background()
	var networks resource.Resource[*networkv1.Network]
	var fakeClient k8sClient.FakeClientset
	var localNodeResource agentK8s.LocalNodeResource

	hive := hive.New(
		cell.Provide(func() multinicconfig.Config {
			return multinicconfig.Config{
				EnableGoogleMultiNIC: true,
			}
		}),
		k8sClient.FakeClientCell,
		multinicclients.FakeMNClientCell,
		agentK8s.ResourcesCell,
		cell.Invoke(func(
			c *k8sClient.FakeClientset,
			nws resource.Resource[*networkv1.Network],
			ln agentK8s.LocalNodeResource,
		) error {
			fakeClient = *c
			networks = nws
			localNodeResource = ln
			return nil
		}),
	)
	tlog := hivetest.Logger(t)
	if err := hive.Start(tlog, ctx); err != nil {
		t.Fatalf("failed to start hive: %v", err)
	}

	// Initialize the BPF map
	if err := multinet.HostDevRoutingMap.OpenOrCreate(); err != nil {
		t.Fatalf("failed to open or create host dev routing map: %v", err)
	}
	defer multinet.HostDevRoutingMap.Unpin()

	testcases := []struct {
		desc                  string
		networkName           string
		interfaceName         string
		interfaceExists       bool
		preExistingErrorCount int
		expectedErrorCount    int
		checkRetryLimit       bool
		configEnabled         bool
		retryLimit            int
		// preExistingRoutes maps interface index to destination CIDR
		preExistingRoutes map[int]string
		// checkRoutesPreserved verifies that pre-existing routes were NOT deleted
		checkRoutesPreserved bool
	}{
		{
			desc:               "interface missing, config enabled",
			networkName:        "net-missing",
			interfaceName:      "eth1",
			interfaceExists:    false,
			expectedErrorCount: 1,
			configEnabled:      true,
		},
		{
			desc:               "interface exists, config enabled",
			networkName:        "net-exists",
			interfaceName:      "eth2",
			interfaceExists:    true,
			expectedErrorCount: 0,
			configEnabled:      true,
		},
		{
			desc:               "interface missing retry limit, config enabled",
			networkName:        "net-missing-retry",
			interfaceName:      "eth3",
			interfaceExists:    false,
			expectedErrorCount: 6,
			checkRetryLimit:    true,
			configEnabled:      true,
			retryLimit:         5,
		},
		{
			desc:               "interface missing infinite retries, config enabled",
			networkName:        "net-missing-infinite",
			interfaceName:      "eth3-infinite",
			interfaceExists:    false,
			expectedErrorCount: 10,
			checkRetryLimit:    true,
			configEnabled:      true,
			retryLimit:         0,
		},
		{
			desc:               "interface missing, config disabled",
			networkName:        "net-missing-disabled",
			interfaceName:      "eth4",
			interfaceExists:    false,
			expectedErrorCount: 0,
			configEnabled:      false,
		},
		{
			desc:                  "interface exists, recovers from failure",
			networkName:           "net-recovered",
			interfaceName:         "eth5",
			interfaceExists:       true,
			preExistingErrorCount: 3,
			expectedErrorCount:    0,
			configEnabled:         true,
		},
		{
			desc:               "interface missing, existing routes preserved",
			networkName:        "net-missing-preserve",
			interfaceName:      "eth6",
			interfaceExists:    false,
			expectedErrorCount: 1,
			configEnabled:      true,
			preExistingRoutes: map[int]string{
				100: "1.2.3.4/32",
			},
			checkRoutesPreserved: true,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.desc, func(t *testing.T) {
			// Clear the BPF map before each test case to ensure isolation
			if err := multinet.HostDevRoutingMap.DeleteAll(); err != nil {
				t.Fatalf("failed to clear host dev routing map: %v", err)
			}

			runTestInNetNS(t, func() {
				nw := &networkv1.Network{
					ObjectMeta: metav1.ObjectMeta{
						Name: tc.networkName,
					},
					Spec: networkv1.NetworkSpec{
						Type: networkv1.L2NetworkType,
						NodeInterfaceMatcher: networkv1.NodeInterfaceMatcher{
							InterfaceName: &tc.interfaceName,
						},
						Gateway4: utilpointer.String("10.0.0.255"),
					},
				}

				// Populate network store
				nwStore, err := networks.Store(ctx)
				if err != nil {
					t.Fatalf("failed to get network store: %v", err)
				}
				if err := nwStore.CacheStore().Add(nw); err != nil {
					t.Fatalf("failed to add network to store: %v", err)
				}

				if tc.interfaceExists {
					// Create dummy interface
					defer cleanupLinks(t, tc.interfaceName)
					l := setupParentLinkWithAttrs(t, netlink.LinkAttrs{Name: tc.interfaceName})

					// Define addr
					addr := &netlink.Addr{IPNet: &net.IPNet{IP: net.ParseIP("10.0.0.1"), Mask: net.CIDRMask(24, 32)}}
					if err := netlink.AddrAdd(l, addr); err != nil {
						t.Fatalf("failed to add address to link: %v,", err)
					}
				}

				testReconciler := NetworkReconciler{
					Clientset:         &fakeClient,
					Networks:          networks,
					LocalNodeResource: localNodeResource,
					Log:               logging.DefaultLogger.WithField(logfields.LogSubsys, "test"),
					networkErrors:     make(map[string]int),
					Config: multinicconfig.Config{
						EnableHostDeviceRoutingReconciliation: tc.configEnabled,
						NetworkReconcilerRetryLimit:           tc.retryLimit,
					},
				}

				if tc.preExistingErrorCount > 0 {
					testReconciler.networkErrors[tc.networkName] = tc.preExistingErrorCount
				}

				if len(tc.preExistingRoutes) > 0 {
					for ifIndex, cidr := range tc.preExistingRoutes {
						_, ipnet, _ := net.ParseCIDR(cidr)
						key := multinet.NewHostDevRoutingKey(uint32(ifIndex), ipnet)
						val := multinet.NewHostDevRoutingEntry(net.ParseIP("10.0.0.1"))
						if err := multinet.HostDevRoutingMap.Update(key, val); err != nil {
							t.Fatalf("failed to update host dev routing map: %v", err)
						}
					}
				}

				iterations := 1
				if tc.checkRetryLimit {
					iterations = 10
				}

				for i := 0; i < iterations; i++ {
					// Simulate logic in reconcileNetwork
					if testReconciler.Config.EnableHostDeviceRoutingReconciliation {
						// We ignore the error from updateHostDeviceRouting because we cannot mock the BPF map easily.
						// We only verify that the logic reached the point of updating networkErrors.
						_ = testReconciler.updateHostDeviceRouting(ctx)
					}
				}

				count := testReconciler.networkErrors[tc.networkName]
				if count != tc.expectedErrorCount {
					t.Errorf("networkErrors[%s] = %d, want %d", tc.networkName, count, tc.expectedErrorCount)
				}

				if tc.checkRoutesPreserved {
					existingRecs, err := existingRoutingRecords()
					if err != nil {
						t.Fatalf("failed to fetch existing records: %v", err)
					}
					if len(existingRecs) != len(tc.preExistingRoutes) {
						t.Errorf("expected %d existing records, got %d. Accidental deletion likely occurred.", len(tc.preExistingRoutes), len(existingRecs))
					}
				}
			})
		})
	}

	if err := hive.Stop(tlog, ctx); err != nil {
		t.Fatalf("failed to stop hive: %v", err)
	}
}
