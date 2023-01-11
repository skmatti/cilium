// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !privileged_tests

package ipcache

import (
	"net"

	"github.com/cilium/cilium/pkg/checker"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/source"
	. "gopkg.in/check.v1"
)

func (s *IPCacheTestSuite) TestIPCacheUpsertRemotePods(c *C) {
	ipc := NewIPCache(&Configuration{
		NodeHandler: &mockNodeHandler{},
	})
	identity := Identity{
		ID:     identity.ReservedIdentityUnmanaged,
		Source: source.KVStore,
	}

	remote1 := net.ParseIP("1.2.3.4")

	// Make sure nothing is updated if there are no remote pods
	ipc.UpsertRemotePods(remote1, []*net.IPNet{})
	c.Assert(len(ipc.ipToIdentityCache), Equals, 0)
	c.Assert(len(ipc.identityToIPCache), Equals, 0)

	// Insert single IPv4 cidr
	cidr24 := "10.1.2.0/24"
	ipc.UpsertRemotePods(remote1, []*net.IPNet{mustParseIPNet(cidr24, c)})
	c.Assert(ipc.ipToHostIPCache[cidr24].IP.String(), Equals, remote1.String())
	c.Assert(ipc.ipToIdentityCache[cidr24].ID, Equals, identity.ID)

	// Insert multiple IPv4 cidrs for same host
	remote2 := net.ParseIP("2.3.4.5")
	cidr16 := "10.2.0.0/16"
	cidr12 := "10.16.0.0/12"
	ipc.UpsertRemotePods(remote2, []*net.IPNet{
		mustParseIPNet(cidr16, c),
		mustParseIPNet(cidr12, c),
	})
	// Make sure the old mappings are still there
	c.Assert(ipc.ipToHostIPCache[cidr24].IP.String(), Equals, remote1.String())
	c.Assert(ipc.ipToIdentityCache[cidr24].ID, Equals, identity.ID)

	// Make sure the new mappings are here now
	c.Assert(ipc.ipToHostIPCache[cidr16].IP.String(), Equals, remote2.String())
	c.Assert(ipc.ipToIdentityCache[cidr16].ID, Equals, identity.ID)
	c.Assert(ipc.ipToHostIPCache[cidr12].IP.String(), Equals, remote2.String())
	c.Assert(ipc.ipToIdentityCache[cidr12].ID, Equals, identity.ID)

	c.Assert(len(ipc.ipToIdentityCache), Equals, 3)

	// All the identities are marked "unmanaged"
	c.Assert(len(ipc.identityToIPCache), Equals, 1)

	// Insert multiple IPv6 cidrs for same host
	remote3 := net.ParseIP("1:2:3:4:aa:bb:cc:dd")
	cidr48 := "10:20:30::/48"
	cidr96 := "50:60:70:80:90::/96"
	ipc.UpsertRemotePods(remote3, []*net.IPNet{
		mustParseIPNet(cidr48, c),
		mustParseIPNet(cidr96, c),
	})

	// Make sure the old mappings are still there
	c.Assert(ipc.ipToHostIPCache[cidr24].IP.String(), Equals, remote1.String())
	c.Assert(ipc.ipToIdentityCache[cidr24].ID, Equals, identity.ID)
	c.Assert(ipc.ipToHostIPCache[cidr16].IP.String(), Equals, remote2.String())
	c.Assert(ipc.ipToIdentityCache[cidr16].ID, Equals, identity.ID)
	c.Assert(ipc.ipToHostIPCache[cidr12].IP.String(), Equals, remote2.String())
	c.Assert(ipc.ipToIdentityCache[cidr12].ID, Equals, identity.ID)

	// Make sure the new mappings are here now
	c.Assert(ipc.ipToHostIPCache[cidr48].IP.String(), Equals, remote3.String())
	c.Assert(ipc.ipToIdentityCache[cidr48].ID, Equals, identity.ID)
	c.Assert(ipc.ipToHostIPCache[cidr96].IP.String(), Equals, remote3.String())
	c.Assert(ipc.ipToIdentityCache[cidr96].ID, Equals, identity.ID)

	c.Assert(len(ipc.ipToIdentityCache), Equals, 5)

	// All the identities are marked "unmanaged"
	c.Assert(len(ipc.identityToIPCache), Equals, 1)
}

func (s *IPCacheTestSuite) TestIPCacheDeleteRemotePods(c *C) {
	ipc := NewIPCache(&Configuration{
		NodeHandler: &mockNodeHandler{},
	})

	// Insert a bunch of stuff
	cidr24 := "10.1.2.0/24"
	remote1 := net.ParseIP("1.2.3.4")
	ipc.UpsertRemotePods(remote1, []*net.IPNet{mustParseIPNet(cidr24, c)})

	remote2 := net.ParseIP("2.3.4.5")
	cidr16 := "10.2.0.0/16"
	cidr12 := "10.16.0.0/12"
	ipc.UpsertRemotePods(remote2, []*net.IPNet{
		mustParseIPNet(cidr16, c),
		mustParseIPNet(cidr12, c),
	})

	remote3 := net.ParseIP("1:2:3:4:aa:bb:cc:dd")
	cidr48 := "10:20:30::/48"
	cidr96 := "50:60:70:80:90::/96"
	ipc.UpsertRemotePods(remote3, []*net.IPNet{
		mustParseIPNet(cidr48, c),
		mustParseIPNet(cidr96, c),
	})

	c.Assert(len(ipc.ipToIdentityCache), Equals, 5)

	// Make sure deleting a non existent node does not change anything.
	nonExistentNode := net.ParseIP("17.18.19.20")
	err := ipc.DeleteRemoteNode(nonExistentNode, nil)
	c.Assert(err, Equals, nil)
	c.Assert(len(ipc.ipToIdentityCache), Equals, 5)

	// Make sure we can not delete a remote node that also hosts cilium-managed pods
	managedPod := "12.13.14.15/32"
	ipc.Upsert(managedPod, remote1, 0, nil, Identity{
		ID:     22,
		Source: source.Kubernetes,
	})
	err = ipc.DeleteRemoteNode(remote1, nil)
	c.Assert(err, Not(Equals), nil)
	c.Assert(err.Error(), checker.PartialMatches, "pod range not sourced from KVStore")

	// Make sure we can delete remote nodes if they are clean
	ipc.Delete(managedPod, source.Kubernetes)
	err = ipc.DeleteRemoteNode(remote1, nil)
	c.Assert(err, Equals, nil)
	_, exists := ipc.LookupByIP(cidr24)
	c.Assert(exists, Equals, false)

	err = ipc.DeleteRemoteNode(remote2, nil)
	c.Assert(err, Equals, nil)
	_, exists = ipc.LookupByIP(cidr16)
	c.Assert(exists, Equals, false)
	_, exists = ipc.LookupByIP(cidr12)
	c.Assert(exists, Equals, false)

	err = ipc.DeleteRemoteNode(nil, remote3)
	c.Assert(err, Equals, nil)
	_, exists = ipc.LookupByIP(cidr48)
	c.Assert(exists, Equals, false)
	_, exists = ipc.LookupByIP(cidr96)
	c.Assert(exists, Equals, false)
}

func mustParseIPNet(s string, c *C) *net.IPNet {
	_, ipNet, err := net.ParseCIDR(s)
	c.Assert(err, Equals, nil)
	return ipNet
}
