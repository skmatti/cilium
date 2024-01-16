// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ciliumidentity

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"k8s.io/apimachinery/pkg/runtime"
	k8sTesting "k8s.io/client-go/testing"
	"k8s.io/client-go/tools/cache"

	ces "github.com/cilium/cilium/operator/pkg/ciliumendpointslice"
	"github.com/cilium/cilium/operator/watchers"
	capi_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/testutils"
)

func TestRegisterController(t *testing.T) {
	testInitLabelsFilter()
	watchersCleanup := testInitWatchers()
	defer watchersCleanup()
	ces.CESliceStore = cache.NewStore(cache.DeletionHandlingMetaNamespaceKeyFunc)
	defer func() {
		ces.CESliceStore = nil
	}()

	ctx := context.Background()
	fakeclient, _ := client.NewFakeClientset()
	createdCID := capi_v2.CiliumIdentity{}
	fakeclient.CiliumFakeClientset.PrependReactor("create", "*", func(action k8sTesting.Action) (handled bool, ret runtime.Object, err error) {
		pa := action.(k8sTesting.CreateAction)
		cid, ok := pa.GetObject().(*capi_v2.CiliumIdentity)
		if ok {
			createdCID = *cid
			log.Infof("createdCID=%+v", createdCID)
		}
		return true, nil, nil
	})

	cidController := NewCIDController(ctx, fakeclient, true, false)
	stopChan := make(chan struct{})
	go cidController.Run(stopChan)
	defer close(stopChan)

	time.Sleep(1 * time.Second)

	verified, err := createPodAndVerifyCIDIsCreated(cidController, &createdCID)
	assert.NoError(t, err)
	assert.Equal(t, true, verified)
}

func createPodAndVerifyCIDIsCreated(cidController *Controller, createdCID *capi_v2.CiliumIdentity) (bool, error) {
	verified := false

	ns := testCreateNSObj("ns1", nil)
	watchers.NSStore.Add(ns)

	pod := testCreatePodObj("pod1", "ns1", testLblsA, nil)
	watchers.PodStore.Add(pod)
	cidController.enqueuePodReconciliation(podResourceKey(pod.Name, pod.Namespace), 0)

	err := testutils.WaitUntil(func() bool {
		return createdCID.Name != ""
	}, time.Second)
	if err != nil {
		return verified, err
	}

	prevCIDName := createdCID.Name
	nsOld := ns.DeepCopy()
	ns.Labels["custom-key"] = "custom-val"
	watchers.PodStore.Update(ns)
	cidController.onNamespaceUpdate(ns, nsOld)

	err = testutils.WaitUntil(func() bool {
		return createdCID.Name != prevCIDName
	}, time.Second)

	verified = err == nil
	return verified, err
}
