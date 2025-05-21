// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ctmap

import (
	"testing"

	"github.com/cilium/ebpf/rlimit"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/maps/google_ctmap"
	"github.com/cilium/cilium/pkg/maps/nat"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/testutils"
	"github.com/cilium/cilium/pkg/tuple"
	"github.com/cilium/cilium/pkg/types"
	"github.com/cilium/cilium/pkg/u8proto"
)

func setupGoogleCtMapPrivilegedTest(tb testing.TB) {
	testutils.PrivilegedTest(tb)

	bpf.CheckOrMountFS("")
	err := rlimit.RemoveMemlock()
	require.Nil(tb, err)
}

// TestCtEgressInfoTcpGC tests whether TCP google_ctmap entries are removed upon a removal of
// their CT entry.
func TestCtEgressInfoTcpGC(t *testing.T) {
	setupGoogleCtMapPrivilegedTest(t)

	// Init maps
	ctMapName := MapNameTCP4Global + "_test"
	natMap := nat.NewMap("cilium_nat_any4_test", nat.IPv4, 1000)
	err := natMap.OpenOrCreate()
	require.Nil(t, err)
	defer natMap.Map.Unpin()

	mapInfo[mapTypeIPv4TCPGlobal] = mapAttributes{
		natMap: natMap, natMapLock: mapInfo[mapTypeIPv4TCPGlobal].natMapLock,
	}

	ctMap := newMap(ctMapName, mapTypeIPv4TCPGlobal)
	err = ctMap.OpenOrCreate()
	require.Nil(t, err)
	defer ctMap.Map.Unpin()

	option.Config.CTMapEntriesGlobalTCP = 1000
	gCtMap := google_ctmap.InitGoogleCtMap()
	err = gCtMap.OpenOrCreate()
	require.Nil(t, err)
	defer gCtMap.Unpin()

	// Create the following entries and check that they get GC-ed:
	//	- CT:	            TCP OUT 192.168.61.11:38193 -> 192.168.61.12:80 <..>
	//	- NAT:              TCP OUT 192.168.61.11:38193 -> 192.168.61.12:80 XLATE_SRC 192.168.61.11:38194
	//	- CtEgressInfo: 	TCP OUT 192.168.61.11:38193 -> 192.168.61.12:80 XLATE_SRC 192.168.61.11:38194
	//		                TCP IN 192.168.61.12:80 -> 192.168.61.11:38194 XLATE_DST 192.168.61.11:38193
	ctKey := &CtKey4Global{
		tuple.TupleKey4Global{
			TupleKey4: tuple.TupleKey4{
				SourceAddr: types.IPv4{192, 168, 61, 12},
				DestAddr:   types.IPv4{192, 168, 61, 11},
				SourcePort: 0x3195,
				DestPort:   0x50,
				NextHeader: u8proto.TCP,
				Flags:      tuple.TUPLE_F_OUT,
			},
		},
	}
	ctVal := &CtEntry{
		Packets:  1,
		Bytes:    216,
		Lifetime: 37459,
	}
	err = ctMap.Map.Update(ctKey, ctVal)
	require.Nil(t, err)

	natKey := &nat.NatKey4{
		TupleKey4Global: tuple.TupleKey4Global{
			TupleKey4: tuple.TupleKey4{
				DestAddr:   types.IPv4{192, 168, 61, 12},
				SourceAddr: types.IPv4{192, 168, 61, 11},
				DestPort:   0x50,
				SourcePort: 0x3195,
				NextHeader: u8proto.TCP,
				Flags:      tuple.TUPLE_F_OUT,
			},
		},
	}
	natVal := &nat.NatEntry4{
		Created: 37400,
		NeedsCT: 1,
		Addr:    types.IPv4{192, 168, 61, 11},
		Port:    0x3295,
	}
	err = natMap.Map.Update(natKey, natVal)
	require.Nil(t, err)

	ctEgressInfoKey1 := &google_ctmap.GoogleCtMapKey4{
		TupleKey4Global: tuple.TupleKey4Global{
			TupleKey4: tuple.TupleKey4{
				SourceAddr: types.IPv4{192, 168, 61, 12},
				DestAddr:   types.IPv4{192, 168, 61, 11},
				SourcePort: 0x3195,
				DestPort:   0x50,
				NextHeader: u8proto.TCP,
				Flags:      tuple.TUPLE_F_OUT,
			},
		},
	}
	ctEgressInfoEntry := &google_ctmap.GoogleCtMapEntry4{
		Ip4Addr: types.IPv4{10, 3, 0, 1},
	}
	err = gCtMap.Update(ctEgressInfoKey1, ctEgressInfoEntry)
	require.Nil(t, err)

	buf := make(map[string][]string)
	err = ctMap.Map.Dump(buf)
	require.Nil(t, err)
	require.Equal(t, 1, len(buf))

	buf = make(map[string][]string)
	err = natMap.Map.Dump(buf)
	require.Nil(t, err)
	require.Equal(t, 1, len(buf))

	var elementCount int
	err = gCtMap.DumpWithCallback(func(k bpf.MapKey, v bpf.MapValue) {
		elementCount++
	})
	require.Nil(t, err)
	require.Equal(t, 1, elementCount)

	// GC and check whether google_ctmap entries have been collected
	filter := &GCFilter{
		RemoveExpired: true,
		Time:          39000,
	}
	stats := doGC4(ctMap, filter)
	require.Equal(t, uint32(0), stats.aliveEntries)
	require.Equal(t, uint32(1), stats.deleted)

	buf = make(map[string][]string)
	err = natMap.Map.Dump(buf)
	require.Nil(t, err)
	require.Equal(t, 0, len(buf))

	elementCount = 0
	err = gCtMap.DumpWithCallback(func(k bpf.MapKey, v bpf.MapValue) {
		elementCount++
	})
	require.Nil(t, err)
	require.Equal(t, 0, elementCount)
}

// TestCtEgressInfoIcmpGC tests whether ICMP google_ctmap entries are removed upon a removal of
// their CT entry.
func TestCtEgressInfoIcmpGC(t *testing.T) {
	setupGoogleCtMapPrivilegedTest(t)

	// Init maps
	ctMapName := MapNameAny4Global + "_test"
	natMap := nat.NewMap("cilium_nat_any4_test", nat.IPv4, 1000)
	err := natMap.OpenOrCreate()
	require.Nil(t, err)
	defer natMap.Map.Unpin()

	mapInfo[mapTypeIPv4AnyGlobal] = mapAttributes{
		natMap: natMap, natMapLock: mapInfo[mapTypeIPv4AnyGlobal].natMapLock,
	}

	ctMap := newMap(ctMapName, mapTypeIPv4AnyGlobal)
	err = ctMap.OpenOrCreate()
	require.Nil(t, err)
	defer ctMap.Map.Unpin()

	option.Config.CTMapEntriesGlobalAny = 1000
	gCtMap := google_ctmap.InitGoogleCtMap()
	err = gCtMap.OpenOrCreate()
	require.Nil(t, err)
	defer gCtMap.Unpin()

	// Create the following entries and check that they get GC-ed:
	//	- CT:	        ICMP OUT 192.168.61.11:38193 -> 192.168.61.12:0 <..>
	//	- NAT:          ICMP OUT 192.168.61.11:38193 -> 192.168.61.12:0 XLATE_SRC <..>
	//	- CtEgressInfo:	ICMP IN 192.168.61.12:0 -> 192.168.61.11:38193 XLATE_DST <..>
	//	 		        ICMP OUT 192.168.61.11:38193 -> 192.168.61.12:0 XLATE_SRC <..>
	ctKey := &CtKey4Global{
		tuple.TupleKey4Global{
			TupleKey4: tuple.TupleKey4{
				SourceAddr: types.IPv4{192, 168, 61, 12},
				DestAddr:   types.IPv4{192, 168, 61, 11},
				SourcePort: 0x3195,
				DestPort:   0,
				NextHeader: u8proto.ICMP,
				Flags:      tuple.TUPLE_F_OUT,
			},
		},
	}
	ctVal := &CtEntry{
		Packets:  1,
		Bytes:    216,
		Lifetime: 37459,
	}
	err = ctMap.Map.Update(ctKey, ctVal)
	require.Nil(t, err)

	natKey := &nat.NatKey4{
		TupleKey4Global: tuple.TupleKey4Global{
			TupleKey4: tuple.TupleKey4{
				DestAddr:   types.IPv4{192, 168, 61, 12},
				SourceAddr: types.IPv4{192, 168, 61, 11},
				DestPort:   0,
				SourcePort: 0x3195,
				NextHeader: u8proto.ICMP,
				Flags:      tuple.TUPLE_F_OUT,
			},
		},
	}
	natVal := &nat.NatEntry4{
		Created: 37400,
		NeedsCT: 1,
		Addr:    types.IPv4{192, 168, 61, 11},
		Port:    0x3195,
	}
	err = natMap.Map.Update(natKey, natVal)
	require.Nil(t, err)

	ctEgressInfoKey1 := &google_ctmap.GoogleCtMapKey4{
		TupleKey4Global: tuple.TupleKey4Global{
			TupleKey4: tuple.TupleKey4{
				SourceAddr: types.IPv4{192, 168, 61, 12},
				DestAddr:   types.IPv4{192, 168, 61, 11},
				SourcePort: 0x3195,
				DestPort:   0,
				NextHeader: u8proto.ICMP,
				Flags:      tuple.TUPLE_F_OUT,
			},
		},
	}
	ctEgressInfoEntry := &google_ctmap.GoogleCtMapEntry4{
		Ip4Addr: types.IPv4{10, 3, 0, 1},
	}
	err = gCtMap.Update(ctEgressInfoKey1, ctEgressInfoEntry)
	require.Nil(t, err)

	buf := make(map[string][]string)
	err = ctMap.Map.Dump(buf)
	require.Nil(t, err)
	require.Equal(t, 1, len(buf))

	buf = make(map[string][]string)
	err = natMap.Map.Dump(buf)
	require.Nil(t, err)
	require.Equal(t, 1, len(buf))

	var elementCount int
	err = gCtMap.DumpWithCallback(func(k bpf.MapKey, v bpf.MapValue) {
		elementCount++
	})
	require.Nil(t, err)
	require.Equal(t, 1, elementCount)

	// GC and check whether google_ctmap entries have been collected
	filter := &GCFilter{
		RemoveExpired: true,
		Time:          39000,
	}
	stats := doGC4(ctMap, filter)
	require.Equal(t, uint32(0), stats.aliveEntries)
	require.Equal(t, uint32(1), stats.deleted)

	buf = make(map[string][]string)
	err = natMap.Map.Dump(buf)
	require.Nil(t, err)
	require.Equal(t, 0, len(buf))

	elementCount = 0
	err = gCtMap.DumpWithCallback(func(k bpf.MapKey, v bpf.MapValue) {
		elementCount++
	})
	require.Nil(t, err)
	require.Equal(t, 0, elementCount)
}

func TestPurgeOrphanGoogleCtEntries(t *testing.T) {
	setupGoogleCtMapPrivilegedTest(t)

	option.Config.CTMapEntriesGlobalTCP = 1000
	option.Config.CTMapEntriesGlobalAny = 1000

	// Init maps
	ctMapTCPName := MapNameTCP4Global + "_test"
	ctMapAnyName := MapNameAny4Global + "_test"

	ctMapTCP := newMap(ctMapTCPName, mapTypeIPv4TCPGlobal)
	err := ctMapTCP.OpenOrCreate()
	require.Nil(t, err)
	defer ctMapTCP.Map.Unpin()

	ctMapAny := newMap(ctMapAnyName, mapTypeIPv4AnyGlobal)
	err = ctMapAny.OpenOrCreate()
	require.Nil(t, err)
	defer ctMapAny.Map.Unpin()

	gCtMap := google_ctmap.InitGoogleCtMap()
	err = gCtMap.OpenOrCreate()
	require.Nil(t, err)
	defer gCtMap.Unpin()

	// 1. TCP entry with a corresponding CT entry (should not be deleted)
	ctKeyTCP := &CtKey4Global{
		tuple.TupleKey4Global{
			TupleKey4: tuple.TupleKey4{
				SourceAddr: types.IPv4{1, 1, 1, 1},
				DestAddr:   types.IPv4{2, 2, 2, 2},
				SourcePort: 1000,
				DestPort:   80,
				NextHeader: u8proto.TCP,
				Flags:      tuple.TUPLE_F_OUT,
			},
		},
	}
	ctValTCP := &CtEntry{Lifetime: 50000}
	err = ctMapTCP.Map.Update(ctKeyTCP, ctValTCP)
	require.Nil(t, err)

	gCtKeyTCP := &google_ctmap.GoogleCtMapKey4{TupleKey4Global: ctKeyTCP.TupleKey4Global}
	gCtEntryTCP := &google_ctmap.GoogleCtMapEntry4{Ip4Addr: types.IPv4{3, 3, 3, 3}}
	err = gCtMap.Update(gCtKeyTCP, gCtEntryTCP)
	require.Nil(t, err)

	// 2. UDP entry with a corresponding CT entry (should not be deleted)
	ctKeyUDP := &CtKey4Global{
		tuple.TupleKey4Global{
			TupleKey4: tuple.TupleKey4{
				SourceAddr: types.IPv4{4, 4, 4, 4},
				DestAddr:   types.IPv4{5, 5, 5, 5},
				SourcePort: 2000,
				DestPort:   53,
				NextHeader: u8proto.UDP,
				Flags:      tuple.TUPLE_F_OUT,
			},
		},
	}
	ctValUDP := &CtEntry{Lifetime: 50000}
	err = ctMapAny.Map.Update(ctKeyUDP, ctValUDP)
	require.Nil(t, err)

	gCtKeyUDP := &google_ctmap.GoogleCtMapKey4{TupleKey4Global: ctKeyUDP.TupleKey4Global}
	gCtEntryUDP := &google_ctmap.GoogleCtMapEntry4{Ip4Addr: types.IPv4{6, 6, 6, 6}}
	err = gCtMap.Update(gCtKeyUDP, gCtEntryUDP)
	require.Nil(t, err)

	// 3. Orphan TCP entry (should be deleted)
	gCtKeyOrphanTCP := &google_ctmap.GoogleCtMapKey4{
		TupleKey4Global: tuple.TupleKey4Global{
			TupleKey4: tuple.TupleKey4{
				SourceAddr: types.IPv4{7, 7, 7, 7},
				DestAddr:   types.IPv4{8, 8, 8, 8},
				SourcePort: 3000,
				DestPort:   80,
				NextHeader: u8proto.TCP,
				Flags:      tuple.TUPLE_F_OUT,
			},
		},
	}
	gCtEntryOrphanTCP := &google_ctmap.GoogleCtMapEntry4{Ip4Addr: types.IPv4{9, 9, 9, 9}}
	err = gCtMap.Update(gCtKeyOrphanTCP, gCtEntryOrphanTCP)
	require.Nil(t, err)

	// 4. Orphan UDP entry (should be deleted)
	gCtKeyOrphanUDP := &google_ctmap.GoogleCtMapKey4{
		TupleKey4Global: tuple.TupleKey4Global{
			TupleKey4: tuple.TupleKey4{
				SourceAddr: types.IPv4{10, 10, 10, 10},
				DestAddr:   types.IPv4{11, 11, 11, 11},
				SourcePort: 4000,
				DestPort:   53,
				NextHeader: u8proto.UDP,
				Flags:      tuple.TUPLE_F_OUT,
			},
		},
	}
	gCtEntryOrphanUDP := &google_ctmap.GoogleCtMapEntry4{Ip4Addr: types.IPv4{12, 12, 12, 12}}
	err = gCtMap.Update(gCtKeyOrphanUDP, gCtEntryOrphanUDP)
	require.Nil(t, err)

	// Verify initial state
	var count int
	err = gCtMap.DumpWithCallback(func(k bpf.MapKey, v bpf.MapValue) {
		count++
	})
	require.Nil(t, err)
	require.Equal(t, 4, count, "Pre-test map should have 4 entries")

	// Run the purge function
	PurgeOrphanGoogleCtEntries(ctMapTCP, ctMapAny)

	// Verify final state
	remainingKeys := make([]google_ctmap.GoogleCtMapKey4, 0)
	err = gCtMap.DumpWithCallback(func(k bpf.MapKey, v bpf.MapValue) {
		remainingKeys = append(remainingKeys, *k.(*google_ctmap.GoogleCtMapKey4))
	})
	require.Nil(t, err)
	require.Len(t, remainingKeys, 2, "Map should have 2 entries after purge")

	// Check that the correct entries remain
	require.Contains(t, remainingKeys, *gCtKeyTCP)
	require.Contains(t, remainingKeys, *gCtKeyUDP)
	require.NotContains(t, remainingKeys, *gCtKeyOrphanTCP)
	require.NotContains(t, remainingKeys, *gCtKeyOrphanUDP)
}
