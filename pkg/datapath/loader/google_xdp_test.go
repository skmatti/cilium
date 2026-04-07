// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package loader

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/testutils"
	"github.com/cilium/cilium/pkg/testutils/netns"
)

func TestRemoveObsoleteNetdevPrograms(t *testing.T) {
	testutils.PrivilegedTest(t)

	ns := netns.NewNetNS(t)

	ns.Do(func() error {
		h, err := netlink.NewHandle()
		require.NoError(t, err)

		veth0 := &netlink.Veth{
			LinkAttrs: netlink.LinkAttrs{Name: "veth0"},
			PeerName:  "veth2",
		}
		err = h.LinkAdd(veth0)
		require.NoError(t, err)

		veth1 := &netlink.Veth{
			LinkAttrs: netlink.LinkAttrs{Name: "veth1"},
			PeerName:  "veth3",
		}
		err = h.LinkAdd(veth1)
		require.NoError(t, err)

		// Create the dummy per-device directories under the standard CiliumPath
		dir0 := bpffsDeviceDir(bpf.CiliumPath(), veth0)
		require.NoError(t, bpf.MkdirBPF(dir0))

		dir1 := bpffsDeviceDir(bpf.CiliumPath(), veth1)
		require.NoError(t, bpf.MkdirBPF(dir1))

		// Call removeObsoleteNetdevPrograms, marking veth1 as an XDP device to protect it
		err = removeObsoleteNetdevPrograms([]string{}, []string{}, []string{"veth1"})
		require.NoError(t, err)

		// Ensure veth0's directory was successfully removed
		_, err = os.Stat(dir0)
		require.True(t, os.IsNotExist(err), "veth0 directory should be removed as obsolete")

		// Ensure veth1's directory was fully preserved
		_, err = os.Stat(dir1)
		require.NoError(t, err, "veth1 directory should be preserved by xdpDevices check")

		err = netlink.LinkDel(veth0)
		require.NoError(t, err)

		err = netlink.LinkDel(veth1)
		require.NoError(t, err)

		return nil
	})
}
