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

package controller

import (
	"context"
	"runtime"
	"testing"
	"time"

	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/google/go-cmp/cmp"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	networkv1 "gke-internal.googlesource.com/anthos-networking/apis/v2/network/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sruntime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	utilpointer "k8s.io/utils/pointer"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	_ "gopkg.in/check.v1"
)

const (
	networkName   = "my-network"
	testNamespace = "test-namespace"
	vlanID100     = 100
	nodeName      = "test-node"
)

var log = logging.DefaultLogger.WithField(logfields.LogSubsys, "test")

func TestEnsureVlanID(t *testing.T) {
	cr := &networkv1.Network{
		ObjectMeta: metav1.ObjectMeta{
			Name:      networkName,
			Namespace: testNamespace,
		},
		Spec: networkv1.NetworkSpec{
			NodeInterfaceMatcher: networkv1.NodeInterfaceMatcher{
				InterfaceName: utilpointer.StringPtr("foo"),
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
		// Specify whether the tagged interface exists before ensureVlanID
		intExists bool
		// Specify whether a tagged interface should exist after ensureVlanID
		expectTag bool
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
	}

	for _, tc := range testcases {
		testFunc := func() {
			defer cleanupLinks(t, expectedIntName, "foo")

			parentLink := setupParentLink(t, "foo")

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

			err := ensureVlanID(tc.networkCR, log)
			if err != nil {
				t.Fatalf("ensureVlanID returned an unexpected error: %s", err)
			}

			var link netlink.Link
			for i := 0; i < 10; i++ {
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
				if link.Attrs().OperState == netlink.OperUp {
					break
				}
				// Add sleep time for the link's operational state to change.
				time.Sleep(500 * time.Millisecond)
			}

			if link.Attrs().OperState != netlink.OperUp {
				t.Fatalf("the tagged interface is not up: %s", link.Attrs().OperState)
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

func TestEnsureVlanIDErrors(t *testing.T) {
	cr := &networkv1.Network{
		ObjectMeta: metav1.ObjectMeta{
			Name:      networkName,
			Namespace: testNamespace,
		},
		Spec: networkv1.NetworkSpec{
			NodeInterfaceMatcher: networkv1.NodeInterfaceMatcher{
				InterfaceName: utilpointer.StringPtr("foo"),
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
				parentInterface: "foo",
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
				defer cleanupLinks(t, expectedIntName, "foo", "foo1")
				setupParentLink(t, "foo")
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

			err := ensureVlanID(tc.networkCR, log)
			if err == nil {
				t.Fatal("ensureVlanID returns nil but want error")
			}
		}
		t.Run(tc.desc, func(t *testing.T) { runTestInNetNS(t, testFunc) })
	}
}

func TestDeleteVlanID(t *testing.T) {
	cr := &networkv1.Network{
		ObjectMeta: metav1.ObjectMeta{
			Name:      networkName,
			Namespace: testNamespace,
		},
		Spec: networkv1.NetworkSpec{
			NodeInterfaceMatcher: networkv1.NodeInterfaceMatcher{
				InterfaceName: utilpointer.StringPtr("foo"),
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
			defer cleanupLinks(t, expectedIntName, "foo")

			parentLink := setupParentLink(t, "foo")

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
			err := deleteVlanID(tc.networkCR, log)
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
	parent := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: parentName}}
	err := netlink.LinkAdd(parent)
	if err != nil {
		t.Fatalf("unable to add parent interface: %s", err)
	}
	parentLink, err := netlink.LinkByName(parentName)
	if err != nil {
		t.Fatalf("unable to find parent interface: %s", err)
	}

	err = netlink.LinkSetUp(parentLink)
	if err != nil {
		t.Fatalf("unable to bring up parent interface: %s", err)
	}

	return parentLink
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

func TestUpdateNodeNetworkAnnotation(t *testing.T) {
	scheme := k8sruntime.NewScheme()
	corev1.AddToScheme(scheme)
	ctx := context.Background()
	testcases := []struct {
		desc                string
		existingAnnotations map[string]string
		nodeName            string
		network             string
		isAdd               bool
		wantErr             string
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
			desc: "add existing network",
			existingAnnotations: map[string]string{
				networkv1.NodeNetworkAnnotationKey: `[{"name":"foo"}]`,
			},
			nodeName: nodeName,
			network:  "foo",
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
			network:  "foo",
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
			nodeName: "foo-node",
			network:  "foo",
			wantErr:  "failed to get k8s node \"test-node\": nodes \"test-node\" not found",
		},
	}
	for _, tc := range testcases {
		t.Run(tc.desc, func(t *testing.T) {
			testNode := corev1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name:        tc.nodeName,
					Annotations: tc.existingAnnotations,
				},
			}
			k8sClient := fake.NewClientBuilder().WithObjects(&testNode).Build()
			testReconciler := NetworkReconciler{
				Client:   k8sClient,
				NodeName: nodeName,
			}
			gotErr := testReconciler.updateNodeNetworkAnnotation(ctx, tc.network, logger, tc.isAdd)
			if gotErr != nil {
				if tc.wantErr == "" {
					t.Fatalf("updateNodeNetworkAnnotation() return error %v but want nil", gotErr)
				}
				if gotErr.Error() != tc.wantErr {
					t.Fatalf("updateNodeNetworkAnnotation() return error %v but want %v", gotErr, tc.wantErr)
				}
				return
			}

			gotNode := &corev1.Node{}
			if err := k8sClient.Get(ctx, types.NamespacedName{Name: tc.nodeName}, gotNode); err != nil {
				t.Fatalf("failed to get k8s node: %v", err)
			}

			if diff := cmp.Diff(gotNode.Annotations, tc.wantAnnotations); diff != "" {
				t.Fatalf("updateNodeNetworkAnnotation() return unexpected output (-got, +want):\n%s", diff)
			}
		})
	}
}
