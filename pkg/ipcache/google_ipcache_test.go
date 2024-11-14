// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipcache

import (
	"context"
	"net"
	"testing"

	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/source"
	"github.com/cilium/cilium/pkg/testutils"
	"github.com/stretchr/testify/assert"
)

func TestIPCacheUpsertRemotePods(t *testing.T) {
	testutils.PrivilegedTest(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ipc := NewIPCache(&Configuration{
		Context:         ctx,
		PolicyHandler:   &mockUpdater{},
		DatapathHandler: &mockTriggerer{},
	})
	id := Identity{
		ID:     identity.ReservedIdentityUnmanaged,
		Source: source.KVStore,
	}

	remote1 := net.ParseIP("1.2.3.4")

	// Make sure nothing is updated if there are no remote pods
	err := ipc.UpsertRemotePods(remote1, []*net.IPNet{})
	assert.Equal(t, err, nil)
	assert.Len(t, ipc.ipToIdentityCache, 0)
	assert.Len(t, ipc.identityToIPCache, 0)

	// Insert single IPv4 cidr
	cidr24 := "10.1.2.0/24"
	err = ipc.UpsertRemotePods(remote1, []*net.IPNet{mustParseIPNet(cidr24, t)})
	assert.Equal(t, err, nil)
	assert.Equal(t, ipc.ipToHostIPCache[cidr24].IP.String(), remote1.String())
	assert.Equal(t, ipc.ipToIdentityCache[cidr24].ID, id.ID)

	// Insert multiple IPv4 cidrs for same host
	remote2 := net.ParseIP("2.3.4.5")
	cidr16 := "10.2.0.0/16"
	cidr12 := "10.16.0.0/12"
	err = ipc.UpsertRemotePods(remote2, []*net.IPNet{
		mustParseIPNet(cidr16, t),
		mustParseIPNet(cidr12, t),
	})
	assert.Equal(t, err, nil)
	// Make sure the old mappings are still there
	assert.Equal(t, ipc.ipToHostIPCache[cidr24].IP.String(), remote1.String())
	assert.Equal(t, ipc.ipToIdentityCache[cidr24].ID, id.ID)

	// Make sure the new mappings are here now
	assert.Equal(t, ipc.ipToHostIPCache[cidr16].IP.String(), remote2.String())
	assert.Equal(t, ipc.ipToIdentityCache[cidr16].ID, id.ID)
	assert.Equal(t, ipc.ipToHostIPCache[cidr12].IP.String(), remote2.String())
	assert.Equal(t, ipc.ipToIdentityCache[cidr12].ID, id.ID)

	assert.Len(t, ipc.ipToIdentityCache, 3)

	// All the identities are marked "unmanaged"
	assert.Len(t, ipc.identityToIPCache, 1)

	// Insert multiple IPv6 cidrs for same host
	remote3 := net.ParseIP("1:2:3:4:aa:bb:cc:dd")
	cidr48 := "10:20:30::/48"
	cidr96 := "50:60:70:80:90::/96"
	err = ipc.UpsertRemotePods(remote3, []*net.IPNet{
		mustParseIPNet(cidr48, t),
		mustParseIPNet(cidr96, t),
	})

	assert.Equal(t, err, nil)

	// Make sure the old mappings are still there
	assert.Equal(t, ipc.ipToHostIPCache[cidr24].IP.String(), remote1.String())
	assert.Equal(t, ipc.ipToIdentityCache[cidr24].ID, id.ID)
	assert.Equal(t, ipc.ipToHostIPCache[cidr16].IP.String(), remote2.String())
	assert.Equal(t, ipc.ipToIdentityCache[cidr16].ID, id.ID)
	assert.Equal(t, ipc.ipToHostIPCache[cidr12].IP.String(), remote2.String())
	assert.Equal(t, ipc.ipToIdentityCache[cidr12].ID, id.ID)

	// Make sure the new mappings are here now
	assert.Equal(t, ipc.ipToHostIPCache[cidr48].IP.String(), remote3.String())
	assert.Equal(t, ipc.ipToIdentityCache[cidr48].ID, id.ID)
	assert.Equal(t, ipc.ipToHostIPCache[cidr96].IP.String(), remote3.String())
	assert.Equal(t, ipc.ipToIdentityCache[cidr96].ID, id.ID)

	assert.Len(t, ipc.ipToIdentityCache, 5)

	// All the identities are marked "unmanaged"
	assert.Len(t, ipc.identityToIPCache, 1)
}

func TestIPCacheDeleteRemotePods(t *testing.T) {
	testutils.PrivilegedTest(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ipc := NewIPCache(&Configuration{
		Context:         ctx,
		PolicyHandler:   &mockUpdater{},
		DatapathHandler: &mockTriggerer{},
	})

	// Insert a bunch of stuff
	cidr24 := "10.1.2.0/24"
	remote1 := net.ParseIP("1.2.3.4")
	err := ipc.UpsertRemotePods(remote1, []*net.IPNet{mustParseIPNet(cidr24, t)})
	assert.Equal(t, err, nil)

	remote2 := net.ParseIP("2.3.4.5")
	cidr16 := "10.2.0.0/16"
	cidr12 := "10.16.0.0/12"
	assert.Equal(t, err, nil)
	err = ipc.UpsertRemotePods(remote2, []*net.IPNet{
		mustParseIPNet(cidr16, t),
		mustParseIPNet(cidr12, t),
	})
	assert.Equal(t, err, nil)

	remote3 := net.ParseIP("1:2:3:4:aa:bb:cc:dd")
	cidr48 := "10:20:30::/48"
	cidr96 := "50:60:70:80:90::/96"
	assert.Equal(t, err, nil)
	err = ipc.UpsertRemotePods(remote3, []*net.IPNet{
		mustParseIPNet(cidr48, t),
		mustParseIPNet(cidr96, t),
	})
	assert.Equal(t, err, nil)

	assert.Equal(t, len(ipc.ipToIdentityCache), 5)

	// Make sure deleting a nonexistent node does not change anything.
	nonExistentNode := net.ParseIP("17.18.19.20")
	err = ipc.DeleteRemoteNode(nonExistentNode, nil)
	assert.Equal(t, err, nil)
	assert.Len(t, ipc.ipToIdentityCache, 5)

	// Make sure we can not delete a remote node that also hosts cilium-managed pods
	managedPod := "12.13.14.15/32"
	_, err = ipc.Upsert(managedPod, remote1, 0, nil, Identity{
		ID:     22,
		Source: source.Kubernetes,
	})
	assert.Equal(t, err, nil)

	deleteErr := ipc.DeleteRemoteNode(remote1, nil)
	assert.NotEqual(t, deleteErr, nil)
	assert.ErrorContains(t, deleteErr, "pod range not sourced from KVStore")

	// Make sure we can delete remote nodes if they are clean
	ipc.Delete(managedPod, source.Kubernetes)
	err = ipc.DeleteRemoteNode(remote1, nil)
	assert.Equal(t, err, nil)
	_, exists := ipc.LookupByIP(cidr24)
	assert.Equal(t, exists, false)

	err = ipc.DeleteRemoteNode(remote2, nil)
	assert.Equal(t, err, nil)
	_, exists = ipc.LookupByIP(cidr16)
	assert.Equal(t, exists, false)
	_, exists = ipc.LookupByIP(cidr12)
	assert.Equal(t, exists, false)

	err = ipc.DeleteRemoteNode(nil, remote3)
	assert.Equal(t, err, nil)
	_, exists = ipc.LookupByIP(cidr48)
	assert.Equal(t, exists, false)
	_, exists = ipc.LookupByIP(cidr96)
	assert.Equal(t, exists, false)
}

func mustParseIPNet(s string, t *testing.T) *net.IPNet {
	_, ipNet, err := net.ParseCIDR(s)
	assert.Equal(t, err, nil)
	return ipNet
}
