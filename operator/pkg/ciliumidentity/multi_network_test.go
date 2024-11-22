package ciliumidentity

import (
	"context"
	"fmt"
	"testing"

	"github.com/cilium/cilium/pkg/labels"
	"github.com/stretchr/testify/assert"
)

var (
	podAnnotations1 = map[string]string{
		"networking.gke.io/default-interface": "eth0",
		"networking.gke.io/interfaces": `
		[{
			"interfaceName": "eth0",
			"network": "default"
		},
		{
			"interfaceName": "eth1",
			"network": "net1"
		}]`,
	}
	podAnnotations2 = map[string]string{
		"networking.gke.io/default-interface": "eth0",
		"networking.gke.io/interfaces": `
		[{
			"interfaceName": "eth0",
			"network": "default"
		},
		{
			"interfaceName": "eth1",
			"network": "net1"
		},
		{
			"interfaceName": "eth2",
			"network": "net2"
		}]`,
	}
	podAnnotations3 = map[string]string{
		"networking.gke.io/default-interface": "eth0",
		"networking.gke.io/interfaces": `
		[{
			"interfaceName": "eth0",
			"network": "default"
		},
		{
			"interfaceName": "eth1",
			"network": "net3"
		},
		{
			"interfaceName": "eth1",
			"network": "net4"
		},
		{
			"interfaceName": "eth2",
			"network": "net5"
		}]`,
	}

	testLblsA = map[string]string{"key-a": "val-1"}
)

func TestReconcileMultiNICPod(t *testing.T) {
	ctx := context.Background()
	reconciler, queueOps, _, cleanupFunc := testNewReconciler(t, ctx, false, true)
	defer cleanupFunc()

	reconciler.nsStore.CacheStore().Add(testCreateNSObj("ns1", nil))

	// Pods with same labels but with different annotations.
	pod1 := testCreatePodObj("pod1", "ns1", testLblsA, podAnnotations1)
	reconciler.podStore.CacheStore().Add(pod1)

	queueOps.fakeWorkQueue = make(map[string]bool)
	assert.NoError(t, reconciler.reconcileMultiNICPod(podResourceKey(pod1.Name, pod1.Namespace)))
	assert.Equal(t, 2, len(queueOps.fakeWorkQueue), "2 CIDs are enqueued for Pod 1 creation")
	testVerifyCIDUsageInPods(t, reconciler.cidUsageInPods, 2, 2)

	pod2 := testCreatePodObj("pod2", "ns1", testLblsA, podAnnotations2)
	reconciler.podStore.CacheStore().Add(pod2)

	queueOps.fakeWorkQueue = make(map[string]bool)
	assert.NoError(t, reconciler.reconcileMultiNICPod(podResourceKey(pod2.Name, pod2.Namespace)))
	assert.Equal(t, 1, len(queueOps.fakeWorkQueue), "1 CID is enqueued for Pod 2 creation")
	testVerifyCIDUsageInPods(t, reconciler.cidUsageInPods, 3, 5)

	pod3 := testCreatePodObj("pod3", "ns1", testLblsA, podAnnotations2)
	reconciler.podStore.CacheStore().Add(pod3)

	queueOps.fakeWorkQueue = make(map[string]bool)
	assert.NoError(t, reconciler.reconcileMultiNICPod(podResourceKey(pod3.Name, pod3.Namespace)))
	assert.Equal(t, 0, len(queueOps.fakeWorkQueue), "0 CIDs is enqueued for Pod 3 creation")
	testVerifyCIDUsageInPods(t, reconciler.cidUsageInPods, 3, 8)

	pod4 := testCreatePodObj("pod4", "ns1", testLblsA, podAnnotations3)
	reconciler.podStore.CacheStore().Add(pod4)
}

func TestGetRelevantLabelsForMultiNICPod(t *testing.T) {
	ctx := context.Background()
	reconciler, _, _, cleanupFunc := testNewReconciler(t, ctx, false, true)
	defer cleanupFunc()

	reconciler.nsStore.CacheStore().Add(testCreateNSObj("ns1", nil))

	pod1 := testCreatePodObj("pod1", "ns1", testLblsA, podAnnotations1)
	reconciler.podStore.CacheStore().Add(pod1)

	mnPods, err := reconciler.getRelevantLabelsForMultiNICPod(pod1)
	assert.NoError(t, err)
	assert.Equal(t, 2, len(mnPods), "There are 2 multi network pods")

	mnPodName1 := fmt.Sprintf("ns1/pod1-default")
	lbls1, exists := mnPods[mnPodName1]
	assert.Equal(t, true, exists, "Multi network pod for default interface exists")

	mnLabelKey := fmt.Sprintf("%s:%s", labels.LabelSourceK8s, labels.MultinicNetwork)
	netName1, exists := lbls1[mnLabelKey]
	assert.Equal(t, true, exists, "Multi network label for default network exists")

	assert.Equal(t, "default", netName1, "Network name is default")

	mnPodName2 := fmt.Sprintf("ns1/pod1-net1")
	lbls2, exists := mnPods[mnPodName2]
	assert.Equal(t, true, exists, "Multi network pod for net1 interface exists")

	netName2, exists := lbls2[mnLabelKey]
	assert.Equal(t, true, exists, "Multi network label for net1 network exists")

	assert.Equal(t, "net1", netName2, "Network name is net1")
}
