// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package datapath

import (
	"context"
	"net"
	"net/netip"
	"testing"

	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/hive"
	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func setupNodeAddressing(t *testing.T, testDevAddrs []tables.DeviceAddress, devs ...tables.Device) (nodeAddressing types.NodeAddressing) {
	h := hive.New(
		statedb.Cell,
		job.Cell,
		// Table[*Device] infrastructure, to be filled with some fakes below.
		cell.Provide(tables.NewDeviceTable),
		cell.Invoke(statedb.RegisterTable[*tables.Device]),
		cell.Provide(func(db *statedb.DB, devices statedb.RWTable[*tables.Device]) statedb.Table[*tables.Device] {
			// Simulate the DevicesController and populate the devices table.
			txn := db.WriteTxn(devices)
			devices.Insert(txn, &tables.Device{
				Index: 1,
				Name:  "cilium_host",
				Flags: net.FlagUp,
				Addrs: []tables.DeviceAddress{
					{Addr: netip.MustParseAddr("9.9.9.9"), Scope: unix.RT_SCOPE_SITE},
					{Addr: netip.MustParseAddr("9.9.9.8"), Scope: unix.RT_SCOPE_LINK},
				},
				Selected: false,
			})
			devices.Insert(txn, &tables.Device{
				Index:    2,
				Name:     "test",
				Flags:    net.FlagUp,
				Addrs:    testDevAddrs,
				Selected: true,
			})
			for _, d := range devs {
				devices.Insert(txn, &d)
			}
			txn.Commit()
			return devices
		}),
		// Table[NodeAddress] and controller that populates it from devices.
		tables.NodeAddressCell,
		// LocalNodeStore as required by Router(), PrimaryExternal(), etc.
		node.LocalNodeStoreCell,
		// option.DaemonConfig needed for AddressMaxScope. This flag will move into NodeAddressConfig
		// in a follow-up PR.
		cell.Provide(func() *option.DaemonConfig {
			return &option.DaemonConfig{
				AddressScopeMax: defaults.AddressScopeMax,
			}
		}),
		NodeAddressingCell,
		cell.Invoke(func(nodeAddressing_ types.NodeAddressing) {
			nodeAddressing = nodeAddressing_
		}),
	)
	tlog := hivetest.Logger(t)
	require.NoError(t, h.Start(tlog, context.TODO()), "Start")
	t.Cleanup(func() {
		h.Stop(tlog, context.TODO())
	})
	return
}

func TestDirectRouting(t *testing.T) {
	directRoutingDevName := "ens4"
	testDevAddrs :=
		[]tables.DeviceAddress{
			{
				Addr:  netip.MustParseAddr("10.10.0.1"),
				Scope: unix.RT_SCOPE_SITE,
			},
		}
	var directRoutingTests = []struct {
		name                  string
		devices               []tables.Device
		isIPv4                bool
		wantDirectRoutingAddr net.IP
	}{
		{
			name: "ipv4_simple",
			devices: []tables.Device{
				{
					Index: 3,
					Name:  directRoutingDevName,
					Flags: net.FlagUp,
					Addrs: []tables.DeviceAddress{
						{
							Addr:  netip.MustParseAddr("10.0.0.1"),
							Scope: unix.RT_SCOPE_SITE,
						},
					},
					Selected: true,
				},
			},
			isIPv4:                true,
			wantDirectRoutingAddr: net.ParseIP("10.0.0.1"),
		},
		{
			name: "ipv6_simple",
			devices: []tables.Device{
				{
					Index: 3,
					Name:  directRoutingDevName,
					Flags: net.FlagUp,
					Addrs: []tables.DeviceAddress{
						{
							Addr:  netip.MustParseAddr("2600:1900:4000:a5ac:0:d::"),
							Scope: unix.RT_SCOPE_SITE,
						},
					},
					Selected: true,
				},
			},
			isIPv4:                false,
			wantDirectRoutingAddr: net.ParseIP("2600:1900:4000:a5ac:0:d::"),
		},
		{
			name: "ipv4_link_local_first",
			devices: []tables.Device{
				{
					Index: 3,
					Name:  directRoutingDevName,
					Flags: net.FlagUp,
					Addrs: []tables.DeviceAddress{
						{
							Addr:  netip.MustParseAddr("169.254.1.10"),
							Scope: unix.RT_SCOPE_SITE,
						},
						{
							Addr:  netip.MustParseAddr("10.0.0.1"),
							Scope: unix.RT_SCOPE_SITE,
						},
					},
					Selected: true,
				},
			},
			isIPv4:                true,
			wantDirectRoutingAddr: net.ParseIP("10.0.0.1"),
		},
		{
			name: "ipv4_link_local_last",
			devices: []tables.Device{
				{
					Index: 3,
					Name:  directRoutingDevName,
					Flags: net.FlagUp,
					Addrs: []tables.DeviceAddress{
						{
							Addr:  netip.MustParseAddr("10.0.0.1"),
							Scope: unix.RT_SCOPE_SITE,
						},
						{
							Addr:  netip.MustParseAddr("169.254.1.10"),
							Scope: unix.RT_SCOPE_SITE,
						},
					},
					Selected: true,
				},
			},
			isIPv4:                true,
			wantDirectRoutingAddr: net.ParseIP("10.0.0.1"),
		},
		{
			name: "ipv6_link_local_first",
			devices: []tables.Device{
				{
					Index: 3,
					Name:  directRoutingDevName,
					Flags: net.FlagUp,
					Addrs: []tables.DeviceAddress{
						{
							Addr:  netip.MustParseAddr("2600:1900:4000:a5ac:0:d::"),
							Scope: unix.RT_SCOPE_SITE,
						},
						{
							Addr:  netip.MustParseAddr("fe80::10d6:7098:7495:f9d4"),
							Scope: unix.RT_SCOPE_SITE,
						},
					},
					Selected: true,
				},
			},
			isIPv4:                false,
			wantDirectRoutingAddr: net.ParseIP("2600:1900:4000:a5ac:0:d::"),
		},
		{
			name: "ipv6_link_local_last",
			devices: []tables.Device{
				{
					Index: 3,
					Name:  directRoutingDevName,
					Flags: net.FlagUp,
					Addrs: []tables.DeviceAddress{
						{
							Addr:  netip.MustParseAddr("fe80::10d6:7098:7495:f9d4"),
							Scope: unix.RT_SCOPE_SITE,
						},
						{
							Addr:  netip.MustParseAddr("2600:1900:4000:a5ac:0:d::"),
							Scope: unix.RT_SCOPE_SITE,
						},
					},
					Selected: true,
				},
			},
			isIPv4:                false,
			wantDirectRoutingAddr: net.ParseIP("2600:1900:4000:a5ac:0:d::"),
		},
	}
	option.Config.DirectRoutingDevice = directRoutingDevName
	for _, tt := range directRoutingTests {
		t.Run(tt.name, func(t *testing.T) {
			nodeAddressing := setupNodeAddressing(t, testDevAddrs, tt.devices...)
			{
				var addr net.IP
				var idx int
				if tt.isIPv4 {
					idx, addr, _ = nodeAddressing.IPv4().DirectRouting()
				} else {
					idx, addr, _ = nodeAddressing.IPv6().DirectRouting()
				}
				require.Equal(t, addr.String(), tt.wantDirectRoutingAddr.String())
				require.Equal(t, tt.devices[0].Index, idx)
			}
		})
	}
}
