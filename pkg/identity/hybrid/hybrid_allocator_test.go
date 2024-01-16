// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package hybrid

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"

	"github.com/cilium/cilium/pkg/identity"
	idcache "github.com/cilium/cilium/pkg/identity/cache"
	"github.com/cilium/cilium/pkg/identity/key"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/watchers"
	"github.com/cilium/cilium/pkg/labels"
)

var (
	testLblsArray labels.LabelArray

	testLblsA = labels.Map2Labels(map[string]string{"key-a": "val-1"}, labels.LabelSourceK8s)
	testLblsB = labels.Map2Labels(map[string]string{"key-b": "val-2"}, labels.LabelSourceK8s)

	nilID *identity.Identity
)

func TestHybridIDAllocator(t *testing.T) {
	watchers.CIDStore = cache.NewIndexer(
		cache.DeletionHandlingMetaNamespaceKeyFunc,
		cache.Indexers{watchers.ByKeyIndex: watchers.GetIdentitiesByKeyFunc((&key.GlobalIdentity{}).PutKeyFromMap)})

	defer func() { watchers.CIDStore = nil }()

	owner := idcache.NewDummyOwner()
	h := NewHybridIDAllocator(owner)
	h.InitIdentityAllocator(nil, nil)
	defer h.Close()
	ctx := context.Background()

	testAllocateAndReleaseIdentity(ctx, t, h)
	testGetIDCacheAndModel(t, h)
	testLookupIdentity(ctx, t, h)
}

func testAllocateAndReleaseIdentity(ctx context.Context, t *testing.T, h *HybridIDAllocator) {
	numID1 := identity.NumericIdentity(500)
	cid1 := &v2.CiliumIdentity{
		ObjectMeta: metav1.ObjectMeta{
			Name:   numID1.String(),
			Labels: testLblsA.StringMap(),
		},
		SecurityLabels: testLblsA.StringMap(),
	}
	watchers.CIDStore.Add(cid1)

	id1, allocated, err := h.AllocateIdentity(ctx, testLblsA, false, identity.InvalidIdentity)
	assert.NoError(t, err)
	assert.Equal(t, true, allocated)
	assert.Equal(t, testLblsA, id1.Labels)

	released, err := h.Release(ctx, id1, false)
	assert.NoError(t, err)
	assert.Equal(t, false, released)

	err = h.ReleaseSlice(ctx, nil, []*identity.Identity{id1})
	assert.NoError(t, err)
}

func testGetIDCacheAndModel(t *testing.T, h *HybridIDAllocator) {
	numID2 := identity.NumericIdentity(1000)
	idCache := h.GetIdentityCache()
	lblsArray, exists := idCache[numID2]
	assert.Equal(t, false, exists)
	assert.Equal(t, testLblsArray, lblsArray)

	idModel := h.GetIdentities()
	for _, id := range idModel {
		assert.NotEqual(t, numID2, id.ID)
	}

	cid1 := &v2.CiliumIdentity{
		ObjectMeta: metav1.ObjectMeta{
			Name:   numID2.String(),
			Labels: testLblsB.StringMap(),
		},
		SecurityLabels: testLblsB.StringMap(),
	}
	watchers.CIDStore.Add(cid1)
	idCache = h.GetIdentityCache()
	lblsArray, exists = idCache[numID2]
	assert.Equal(t, false, exists)
	assert.Equal(t, testLblsArray, lblsArray)

	idModel = h.GetIdentities()
	for _, id := range idModel {
		assert.NotEqual(t, numID2, id.ID)
	}

	watchers.CIDInformerIsSynced = true
	defer func() { watchers.CIDInformerIsSynced = false }()
	idCache = h.GetIdentityCache()
	lblsArray, exists = idCache[numID2]
	assert.Equal(t, true, exists)
	assert.Equal(t, testLblsB.LabelArray(), lblsArray)

	idModel = h.GetIdentities()
	foundID := false
	for _, id := range idModel {
		if numID2 == identity.NumericIdentity(id.ID) {
			foundID = true
			break
		}
	}
	assert.Equal(t, true, foundID)
}

func testLookupIdentity(ctx context.Context, t *testing.T, h *HybridIDAllocator) {
	id1, allocated, err := h.AllocateIdentity(ctx, testLblsA, false, identity.InvalidIdentity)
	assert.NoError(t, err)
	assert.Equal(t, true, allocated)
	assert.Equal(t, testLblsA, id1.Labels)

	id := h.LookupIdentity(ctx, testLblsA)
	assert.Equal(t, nilID, id)

	id = h.LookupIdentityByID(ctx, id1.ID)
	assert.Equal(t, nilID, id)

	watchers.CIDInformerIsSynced = true
	defer func() { watchers.CIDInformerIsSynced = false }()

	id = h.LookupIdentity(ctx, testLblsA)
	assert.Equal(t, id1, id)

	id = h.LookupIdentityByID(ctx, id1.ID)
	assert.Equal(t, id1, id)

	id = h.LookupIdentity(ctx, labels.LabelHost)
	assert.Equal(t, identity.NumericIdentity(1), id.ID, "Reserved ID")

	id = h.LookupIdentity(ctx, testLblsB)
	assert.Equal(t, identity.NumericIdentity(1000), id.ID, "ID from watcher store")

	id = h.LookupIdentityByID(ctx, identity.NumericIdentity(5000))
	assert.Equal(t, nilID, id, "Non existant ID")

	id = h.LookupIdentityByID(ctx, identity.IdentityUnknown)
	_, exists := id.Labels[labels.IDNameUnknown]
	assert.Equal(t, true, exists, "Unknown ID")

	id = h.LookupIdentityByID(ctx, identity.NumericIdentity(1000))
	assert.Equal(t, testLblsB, id.Labels, "ID from watcher store")

	id = h.LookupIdentityByID(ctx, identity.NumericIdentity(1))
	assert.Equal(t, labels.LabelHost, id.Labels, "Reserved ID")

	id = h.LookupIdentityByID(ctx, identity.NumericIdentity(1<<24))
	assert.Equal(t, nilID, id, "Local ID")

	numID2 := identity.NumericIdentity(900)
	cid2 := &v2.CiliumIdentity{
		ObjectMeta: metav1.ObjectMeta{
			Name:   numID2.String(),
			Labels: testLblsB.StringMap(),
		},
		SecurityLabels: testLblsB.StringMap(),
	}
	watchers.CIDStore.Add(cid2)

	id = h.LookupIdentity(ctx, testLblsB)
	assert.Equal(t, numID2, id.ID, "ID from watcher store")
}
