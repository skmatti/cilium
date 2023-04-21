// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !privileged_tests

package ciliumendpointslice

import (
	"testing"

	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/google/go-cmp/cmp"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"
)

func createCESWithIDs(cesName string, ids []int64) *v2alpha1.CiliumEndpointSlice {
	ces := &v2alpha1.CiliumEndpointSlice{ObjectMeta: metav1.ObjectMeta{Name: cesName}}
	for _, id := range ids {
		cep := v2alpha1.CoreCiliumEndpoint{IdentityID: id}
		ces.Endpoints = append(ces.Endpoints, cep)
	}
	return ces
}

func assertEqualIDs(t *testing.T, wantIdentities, gotIdentities map[string]bool) {
	t.Helper()
	if diff := cmp.Diff(wantIdentities, gotIdentities); diff != "" {
		t.Errorf("Unexpected Identites in the CES store (-want +got): \n%s", diff)
	}
}

func TestUsedIdentitiesInCESs(t *testing.T) {
	cesStore := cache.NewStore(cache.DeletionHandlingMetaNamespaceKeyFunc)

	// Empty store.
	gotIdentities := usedIdentitiesInCESs(cesStore)
	wantIdentities := make(map[string]bool)
	assertEqualIDs(t, wantIdentities, gotIdentities)

	// 5 IDs in the store.
	cesA := createCESWithIDs("cesA", []int64{1, 2, 3, 4, 5})
	cesStore.Add(cesA)
	wantIdentities["1"] = true
	wantIdentities["2"] = true
	wantIdentities["3"] = true
	wantIdentities["4"] = true
	wantIdentities["5"] = true
	gotIdentities = usedIdentitiesInCESs(cesStore)
	assertEqualIDs(t, wantIdentities, gotIdentities)

	// 10 IDs in the store.
	cesB := createCESWithIDs("cesB", []int64{10, 20, 30, 40, 50})
	cesStore.Add(cesB)
	wantIdentities["10"] = true
	wantIdentities["20"] = true
	wantIdentities["30"] = true
	wantIdentities["40"] = true
	wantIdentities["50"] = true
	gotIdentities = usedIdentitiesInCESs(cesStore)
	assertEqualIDs(t, wantIdentities, gotIdentities)
}
