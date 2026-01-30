// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipcache

import (
	"context"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/source"
)

func TestMultiNICHostInjectLabels(t *testing.T) {
	option.Config.EnableGoogleMultiNICHostFirewall = true
	defer func() {
		option.Config.EnableGoogleMultiNICHostFirewall = false
	}()
	// Adds kube API server label.
	cancel := setupTest(t)
	defer cancel()
	ctx := context.Background()

	// Define multi nic host variables and initialize an identity
	nodeNetwork := "test-node-network1"
	multiNicID := identity.NumericIdentity(135)
	multiNicLbls := labels.NewReservedMultiNICHostLabels(nodeNetwork)
	bothHostLbls := multiNicLbls.LabelArray().DeepCopy().Labels()
	bothHostLbls.MergeLabels(labels.LabelHost)
	err := identity.InitMultiNICHostNumericIdentitySet(map[string]string{
		multiNicID.String(): nodeNetwork,
	})
	assert.NoError(t, err)
	defer identity.DeleteReservedIdentity(multiNicID)

	assert.Equal(t, bothHostLbls.LabelArray(), identity.LookupReservedIdentity(multiNicID).LabelArray)

	// Add host idenitity to IP 11.0.0.1/32.
	hostEPPrefix := netip.MustParsePrefix("11.0.0.1/32")
	IPIdentityCache.metadata.upsertLocked(hostEPPrefix, source.Local, "node-uid", labels.LabelHost)
	assert.Len(t, IPIdentityCache.metadata.m, 2)
	remaining, err := IPIdentityCache.doInjectLabels(ctx, []netip.Prefix{hostEPPrefix})
	assert.NoError(t, err)
	assert.Len(t, remaining, 0)
	assert.Equal(t, identity.ReservedIdentityHost, IPIdentityCache.ipToIdentityCache[hostEPPrefix.String()].ID)
	// Validate labels in selector cache.
	assert.Equal(t, labels.LabelHost.LabelArray(), PolicyHandler.identities[identity.ReservedIdentityHost])

	// Add multinic-host identity to IP 11.0.0.1/32.
	lbls := multiNicLbls.LabelArray().DeepCopy().Labels()
	// This label will be removed during label injection.
	lbls.MergeLabels(labels.LabelWorld)
	IPIdentityCache.metadata.upsertLocked(hostEPPrefix, source.Local, "multinic-host-uid", lbls)
	assert.Len(t, IPIdentityCache.metadata.m, 2)
	remaining, err = IPIdentityCache.doInjectLabels(ctx, []netip.Prefix{hostEPPrefix})
	assert.NoError(t, err)
	assert.Len(t, remaining, 0)
	assert.Equal(t, multiNicID, IPIdentityCache.ipToIdentityCache[hostEPPrefix.String()].ID)
	// Validate labels in selector cache.
	assert.Equal(t, bothHostLbls.LabelArray(), PolicyHandler.identities[multiNicID])
}

// Test that when multiple IPs have the `resolved:host` and multi nic host
// labels, we correctly aggregate all labels *and* update the selector cache.
// This reproduces GH-28259.
func TestUpdateLocalNodeForMultiNICHost(t *testing.T) {
	option.Config.EnableGoogleMultiNICHostFirewall = true
	defer func() {
		option.Config.EnableGoogleMultiNICHostFirewall = false
	}()
	cancel := setupTest(t)
	defer cancel()
	ctx := context.Background()

	nodeNetwork := "test-node-network2"
	multiNicID := identity.NumericIdentity(145)
	// Multi NIC host label only.
	multiNicLbls := labels.NewReservedMultiNICHostLabels(nodeNetwork)
	// Multi NIC host and local host labels.
	bothHostLbls := labels.NewReservedMultiNICHostLabels(nodeNetwork)
	bothHostLbls.MergeLabels(labels.LabelHost)
	// Local host and k8s API server labels.
	hostK8sAPILbls := labels.Labels{}
	hostK8sAPILbls.MergeLabels(labels.LabelHost)
	hostK8sAPILbls.MergeLabels(labels.LabelKubeAPIServer)

	// Initialize multi nic host identity.
	err := identity.InitMultiNICHostNumericIdentitySet(map[string]string{
		multiNicID.String(): nodeNetwork,
	})
	assert.NoError(t, err)
	defer identity.DeleteReservedIdentity(multiNicID)

	// Helper functions to reduce duplication.
	selectorCacheHas := func(nid identity.NumericIdentity, lbls labels.Labels) {
		t.Helper()
		id := PolicyHandler.identities[nid]
		assert.NotNil(t, id)
		assert.Equal(t, lbls.LabelArray(), id)
	}

	injectLabels := func(ip netip.Prefix, nid identity.NumericIdentity) {
		t.Helper()
		remaining, err := IPIdentityCache.doInjectLabels(ctx, []netip.Prefix{ip})
		assert.NoError(t, err)
		assert.Len(t, remaining, 0)
		assert.Equal(t, nid, IPIdentityCache.ipToIdentityCache[ip.String()].ID)
	}

	idIs := func(ip netip.Prefix, id identity.NumericIdentity) {
		t.Helper()
		assert.Equal(t, id, IPIdentityCache.ipToIdentityCache[ip.String()].ID)
	}

	// Mark .4 as local host
	IPIdentityCache.metadata.upsertLocked(inClusterPrefix, source.Local, "node-uid", labels.LabelHost)
	injectLabels(inClusterPrefix, identity.ReservedIdentityHost)
	idIs(inClusterPrefix, identity.ReservedIdentityHost)
	selectorCacheHas(identity.ReservedIdentityHost, labels.LabelHost)

	// Mark .4 as kube-apiserver
	// Note that in the actual code, we use `source.KubeAPIServer`. However,
	// we use the same source in test case to try and ferret out more bugs.
	IPIdentityCache.metadata.upsertLocked(inClusterPrefix, source.Local, "kube-uid", labels.LabelKubeAPIServer)
	injectLabels(inClusterPrefix, identity.ReservedIdentityHost)
	idIs(inClusterPrefix, identity.ReservedIdentityHost)
	selectorCacheHas(identity.ReservedIdentityHost, hostK8sAPILbls)

	// Mark .5 as local host
	IPIdentityCache.metadata.upsertLocked(inClusterPrefix2, source.Local, "node-uid", labels.LabelHost)
	injectLabels(inClusterPrefix2, identity.ReservedIdentityHost)
	idIs(inClusterPrefix, identity.ReservedIdentityHost)
	idIs(inClusterPrefix2, identity.ReservedIdentityHost)
	selectorCacheHas(identity.ReservedIdentityHost, hostK8sAPILbls)

	// Mark 11.0.0.6/32 as local host
	hostEPPrefix := netip.MustParsePrefix("11.0.0.6/32")
	IPIdentityCache.metadata.upsertLocked(hostEPPrefix, source.Local, "node-uid", labels.LabelHost)
	injectLabels(hostEPPrefix, identity.ReservedIdentityHost)
	idIs(inClusterPrefix, identity.ReservedIdentityHost)
	idIs(inClusterPrefix2, identity.ReservedIdentityHost)
	idIs(hostEPPrefix, identity.ReservedIdentityHost)
	selectorCacheHas(identity.ReservedIdentityHost, hostK8sAPILbls)

	// Add multi nic host to 11.0.0.6/32
	IPIdentityCache.metadata.upsertLocked(hostEPPrefix, source.Local, "multinic-host-uid", multiNicLbls)
	injectLabels(hostEPPrefix, multiNicID)
	idIs(inClusterPrefix, identity.ReservedIdentityHost)
	idIs(inClusterPrefix2, identity.ReservedIdentityHost)
	idIs(hostEPPrefix, multiNicID)
	selectorCacheHas(identity.ReservedIdentityHost, hostK8sAPILbls)
	selectorCacheHas(multiNicID, bothHostLbls)

	// remove kube-apiserver from .4
	IPIdentityCache.metadata.remove(inClusterPrefix, "kube-uid", labels.LabelKubeAPIServer)
	injectLabels(inClusterPrefix, identity.ReservedIdentityHost)
	idIs(inClusterPrefix, identity.ReservedIdentityHost)
	idIs(inClusterPrefix2, identity.ReservedIdentityHost)
	idIs(hostEPPrefix, multiNicID)
	selectorCacheHas(identity.ReservedIdentityHost, labels.LabelHost)
	selectorCacheHas(multiNicID, bothHostLbls)

	// add kube-apiserver back to .4
	IPIdentityCache.metadata.upsertLocked(inClusterPrefix, source.Local, "kube-uid", labels.LabelKubeAPIServer)
	injectLabels(inClusterPrefix, identity.ReservedIdentityHost)
	idIs(inClusterPrefix, identity.ReservedIdentityHost)
	idIs(inClusterPrefix2, identity.ReservedIdentityHost)
	idIs(hostEPPrefix, multiNicID)
	selectorCacheHas(identity.ReservedIdentityHost, hostK8sAPILbls)
	selectorCacheHas(multiNicID, bothHostLbls)

	// add multi-nic host label to .4 and verify that .4 now has multi-nic host
	IPIdentityCache.metadata.upsertLocked(inClusterPrefix, source.Local, "multinic-host-uid", multiNicLbls)
	injectLabels(inClusterPrefix, multiNicID)
	idIs(inClusterPrefix, multiNicID)
	idIs(inClusterPrefix2, identity.ReservedIdentityHost)
	idIs(hostEPPrefix, multiNicID)
	selectorCacheHas(identity.ReservedIdentityHost, labels.LabelHost)
	selectorCacheHas(multiNicID, bothHostLbls)
}
