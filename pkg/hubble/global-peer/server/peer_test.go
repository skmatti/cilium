// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package server

import (
	"testing"
	"time"

	"github.com/cilium/cilium/pkg/datapath/fake"
	v1 "github.com/cilium/cilium/pkg/gke/apis/nodepool/v1"
	"github.com/cilium/cilium/pkg/node/types"
	"github.com/google/go-cmp/cmp"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"
	"k8s.io/utils/pointer"
)

var (
	allNodes = []v1.Node{
		{
			Address: "10.0.0.1",
		},
		{
			Address: "10.0.0.2",
			K8sIP:   pointer.String("10.0.0.3"),
		},
		{
			Address: "10.0.0.4",
		},
	}
	updateNodes = allNodes[:2]

	baseNodePool = &v1.NodePool{
		Spec: v1.NodePoolSpec{
			ClusterName: "base-cluster-name",
			Nodes:       allNodes,
		},
	}
	updateNodePool = &v1.NodePool{
		Spec: v1.NodePoolSpec{
			ClusterName: "base-cluster-name",
			Nodes:       updateNodes,
		},
	}
	emptyNodePool = &v1.NodePool{
		Spec: v1.NodePoolSpec{
			ClusterName: "base-cluster-name",
		},
	}

	differentNodePool = &v1.NodePool{
		Spec: v1.NodePoolSpec{
			ClusterName: "different-cluster-name",
			Nodes: []v1.Node{
				{Address: "10.1.0.1"},
			},
		},
	}
	differentNodePoolDuplicateNode = &v1.NodePool{
		Spec: v1.NodePoolSpec{
			ClusterName: "different-cluster-name",
			Nodes:       allNodes[:1],
		},
	}

	initialNodes = map[string]types.Node{
		"10.0.0.1": v1ToNode(baseNodePool.Spec.ClusterName, allNodes[0].Address),
		"10.0.0.3": v1ToNode(baseNodePool.Spec.ClusterName, *allNodes[1].K8sIP),
		"10.0.0.4": v1ToNode(baseNodePool.Spec.ClusterName, allNodes[2].Address),
	}
	afterNodeUpdate = map[string]types.Node{
		"10.0.0.1": v1ToNode(baseNodePool.Spec.ClusterName, allNodes[0].Address),
		"10.0.0.3": v1ToNode(baseNodePool.Spec.ClusterName, *allNodes[1].K8sIP),
	}
	afterNodeUpdateWithDifferentCluster = map[string]types.Node{
		"10.0.0.1": v1ToNode(baseNodePool.Spec.ClusterName, allNodes[0].Address),
		"10.0.0.3": v1ToNode(baseNodePool.Spec.ClusterName, *allNodes[1].K8sIP),
		"10.1.0.1": v1ToNode(differentNodePool.Spec.ClusterName, "10.1.0.1"),
	}
	afterNodeDelete = map[string]types.Node{}

	handlerInitialNodes     = convertToHandlerNodes(initialNodes)
	handlerAfterUpdateNodes = convertToHandlerNodes(afterNodeUpdate)
)

func convertToHandlerNodes(src map[string]types.Node) (dst map[string]types.Node) {
	dst = make(map[string]types.Node)
	for _, node := range src {
		dst[node.Name] = node
	}
	return
}

func TestGlobalPeerNotifier_Add(t *testing.T) {
	logger, _ := test.NewNullLogger()
	gp := newGlobalPeerNotifier(logger)

	gp.nodePoolAdd(baseNodePool)
	if diff := cmp.Diff(gp.nodes, initialNodes); diff != "" {
		t.Fatalf("Mismatch after processing initial NodePoolAdd (-want, +got):\n%v", diff)
	}
}

func TestGlobalPeerNotifier_UpdateTwiceHasNoEffect(t *testing.T) {
	logger, _ := test.NewNullLogger()
	gp := newGlobalPeerNotifier(logger)
	for k, v := range initialNodes {
		gp.nodes[k] = v
	}

	gp.nodePoolUpdate(baseNodePool, updateNodePool)
	if diff := cmp.Diff(gp.nodes, afterNodeUpdate); diff != "" {
		t.Fatalf("Mismatch after processing NodePoolUpdate (-want, +got):\n%v", diff)
	}

	gp.nodePoolUpdate(baseNodePool, updateNodePool)
	if diff := cmp.Diff(gp.nodes, afterNodeUpdate); diff != "" {
		t.Fatalf("Mismatch after processing NodePoolUpdate (-want, +got):\n%v", diff)
	}
}

func TestGlobalPeerNotifier_Update(t *testing.T) {
	testcases := []struct {
		name          string
		before, after map[string]types.Node
		old, curr     *v1.NodePool
	}{
		{
			name:   "Add new node (with correct old entry)",
			before: initialNodes,
			old:    baseNodePool,
			curr:   updateNodePool,
			after:  afterNodeUpdate,
		},
		{
			name:   "Add new node (without old entry)",
			before: initialNodes,
			old:    emptyNodePool,
			curr:   updateNodePool,
			after:  afterNodeUpdate,
		},
		{
			name:   "Duplicate node from different cluster has no effect",
			before: afterNodeUpdate,
			old:    differentNodePool,
			curr:   differentNodePoolDuplicateNode,
			after:  afterNodeUpdate,
		},
		{
			name:   "Unexpected cluster name change is still processed",
			before: afterNodeUpdate,
			old:    emptyNodePool,
			curr:   differentNodePool,
			after:  afterNodeUpdateWithDifferentCluster,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			logger, _ := test.NewNullLogger()
			gp := newGlobalPeerNotifier(logger)
			for k, v := range tc.before {
				gp.nodes[k] = v
			}

			gp.nodePoolUpdate(tc.old, tc.curr)
			if diff := cmp.Diff(gp.nodes, tc.after); diff != "" {
				t.Fatalf("Mismatch after processing NodePoolUpdate (-want, +got):\n%v", diff)
			}
		})
	}
}

func TestGlobalPeerNotifier_Delete(t *testing.T) {
	logger, _ := test.NewNullLogger()
	gp := newGlobalPeerNotifier(logger)
	for k, v := range afterNodeUpdateWithDifferentCluster {
		gp.nodes[k] = v
	}

	gp.nodePoolDelete(differentNodePool)
	if diff := cmp.Diff(gp.nodes, afterNodeUpdate); diff != "" {
		t.Fatalf("Mismatch after processing NodePoolDelete (-want, +got):\n%v", diff)
	}

	gp.nodePoolDelete(baseNodePool)
	if diff := cmp.Diff(gp.nodes, afterNodeDelete); diff != "" {
		t.Fatalf("Mismatch after processing NodePoolDelete (-want, +got):\n%v", diff)
	}
}

func TestGlobalPeerNotifier_SubscribedFromStart(t *testing.T) {
	logger, _ := test.NewNullLogger()
	gp := newGlobalPeerNotifier(logger)

	handler := fake.NewNodeHandler().(*fake.FakeNodeHandler)
	gp.Subscribe(handler)

	gp.nodePoolAdd(baseNodePool)
	if diff := cmp.Diff(handler.Nodes, handlerInitialNodes); diff != "" {
		t.Fatalf("Mismatch after processing initial NodePoolAdd (-want, +got):\n%v", diff)
	}

	gp.nodePoolUpdate(baseNodePool, updateNodePool)
	if diff := cmp.Diff(handler.Nodes, handlerAfterUpdateNodes); diff != "" {
		t.Fatalf("Mismatch after processing NodePoolUpdate (-want, +got):\n%v", diff)
	}

	gp.nodePoolDelete(baseNodePool)
	if diff := cmp.Diff(handler.Nodes, afterNodeDelete); diff != "" {
		t.Fatalf("Mismatch after processing NodePoolDelete (-want, +got):\n%v", diff)
	}
}

func hasNodeCountFactory(nh *fake.FakeNodeHandler) func(count int) func() bool {
	return func(count int) func() bool {
		return func() bool { return count == len(nh.Nodes) }
	}
}

func TestGlobalPeerNotifier_SubscribedAfterNew(t *testing.T) {
	logger, _ := test.NewNullLogger()
	gp := newGlobalPeerNotifier(logger)

	gp.nodePoolAdd(baseNodePool)

	handler := fake.NewNodeHandler().(*fake.FakeNodeHandler)
	hasNodeCount := hasNodeCountFactory(handler)
	gp.Subscribe(handler)
	assert.Eventually(t, hasNodeCount(3), time.Minute, 10*time.Millisecond)
	if diff := cmp.Diff(handler.Nodes, handlerInitialNodes); diff != "" {
		t.Fatalf("Mismatch after processing initial NodePoolAdd (-want, +got):\n%v", diff)
	}

	gp.nodePoolUpdate(baseNodePool, updateNodePool)
	if diff := cmp.Diff(handler.Nodes, handlerAfterUpdateNodes); diff != "" {
		t.Fatalf("Mismatch after processing NodePoolUpdate (-want, +got):\n%v", diff)
	}

	gp.nodePoolDelete(baseNodePool)
	assert.Empty(t, handler.Nodes)
}

func TestGlobalPeerNotifier_SubscribedAfterUpdate(t *testing.T) {
	logger, _ := test.NewNullLogger()
	gp := newGlobalPeerNotifier(logger)

	gp.nodePoolAdd(baseNodePool)
	gp.nodePoolUpdate(baseNodePool, updateNodePool)

	handler := fake.NewNodeHandler().(*fake.FakeNodeHandler)
	hasNodeCount := hasNodeCountFactory(handler)
	gp.Subscribe(handler)
	assert.Eventually(t, hasNodeCount(2), time.Minute, 10*time.Millisecond)
	if diff := cmp.Diff(handler.Nodes, handlerAfterUpdateNodes); diff != "" {
		t.Fatalf("Mismatch after processing NodePoolUpdate (-want, +got):\n%v", diff)
	}

	gp.nodePoolDelete(baseNodePool)
	assert.Empty(t, handler.Nodes)
}

func TestGlobalPeerNotifier_TwoHandlers(t *testing.T) {
	logger, _ := test.NewNullLogger()
	gp := newGlobalPeerNotifier(logger)

	gp.nodePoolAdd(baseNodePool)

	handlerA := fake.NewNodeHandler().(*fake.FakeNodeHandler)
	hasNodeCountA := hasNodeCountFactory(handlerA)
	gp.Subscribe(handlerA)
	assert.Eventually(t, hasNodeCountA(3), time.Minute, 10*time.Millisecond)
	if diff := cmp.Diff(handlerA.Nodes, handlerInitialNodes); diff != "" {
		t.Fatalf("Mismatch after processing initial NodePoolAdd (-want, +got):\n%v", diff)
	}

	gp.nodePoolUpdate(baseNodePool, updateNodePool)
	handlerB := fake.NewNodeHandler().(*fake.FakeNodeHandler)
	hasNodeCountB := hasNodeCountFactory(handlerB)
	gp.Subscribe(handlerB)
	assert.Equal(t, 2, len(handlerA.Nodes))
	assert.Eventually(t, hasNodeCountB(2), time.Minute, 10*time.Millisecond)
	if diff := cmp.Diff(handlerA.Nodes, handlerAfterUpdateNodes); diff != "" {
		t.Fatalf("Mismatch after processing NodePoolUpdate (-want, +got):\n%v", diff)
	}
	if diff := cmp.Diff(handlerB.Nodes, handlerAfterUpdateNodes); diff != "" {
		t.Fatalf("Mismatch after processing NodePoolUpdate (-want, +got):\n%v", diff)
	}

	gp.nodePoolDelete(baseNodePool)
	assert.Empty(t, handlerA.Nodes)
	assert.Empty(t, handlerB.Nodes)
}

func TestGlobalPeerNotifier_Unsubscribe(t *testing.T) {
	logger, _ := test.NewNullLogger()
	gp := newGlobalPeerNotifier(logger)

	gp.nodePoolAdd(baseNodePool)

	handler := fake.NewNodeHandler().(*fake.FakeNodeHandler)
	hasNodeCount := hasNodeCountFactory(handler)
	gp.Subscribe(handler)
	assert.Eventually(t, hasNodeCount(3), time.Minute, 10*time.Millisecond)
	if diff := cmp.Diff(handler.Nodes, handlerInitialNodes); diff != "" {
		t.Fatalf("Mismatch after processing initial NodePoolAdd (-want, +got):\n%v", diff)
	}

	gp.nodePoolUpdate(baseNodePool, updateNodePool)
	if diff := cmp.Diff(handler.Nodes, handlerAfterUpdateNodes); diff != "" {
		t.Fatalf("Mismatch after processing NodePoolUpdate (-want, +got):\n%v", diff)
	}

	gp.Unsubscribe(handler)

	gp.nodePoolDelete(baseNodePool)
	assert.Equal(t, 2, len(handler.Nodes))
}

func TestGlobalPeerNotifier_UnsubscribeNonExisting(t *testing.T) {
	logger, _ := test.NewNullLogger()
	gp := newGlobalPeerNotifier(logger)

	handler := fake.NewNodeHandler().(*fake.FakeNodeHandler)
	gp.Unsubscribe(handler)
	assert.Empty(t, gp.handlers)
}
