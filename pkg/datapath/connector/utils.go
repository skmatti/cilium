// Copyright 2021 Authors of Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package connector

import (
	"fmt"

	"github.com/cilium/cilium/pkg/datapath/link"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// ProgMapIndex is the map index to load a bpf program.
type ProgMapIndex int

const (
	// EgressMapIndex specificies the map index for the egress direction.
	EgressMapIndex ProgMapIndex = iota
	// IngressMapIndex specificies the map index for the ingress direction.
	IngressMapIndex
	bpfFilterName = "polEntry"
)

func clsactQdisc(index int) *netlink.GenericQdisc {
	qdiscAttrs := netlink.QdiscAttrs{
		LinkIndex: index,
		Handle:    netlink.MakeHandle(0xffff, 0),
		Parent:    netlink.HANDLE_CLSACT,
	}
	return &netlink.GenericQdisc{
		QdiscAttrs: qdiscAttrs,
		QdiscType:  "clsact",
	}
}

func getEntryProgInstructions(fd int, mapIndex int32) asm.Instructions {
	return asm.Instructions{
		asm.LoadMapPtr(asm.R2, fd),
		asm.Mov.Imm(asm.R3, mapIndex),
		asm.FnTailCall.Call(),
		asm.Mov.Imm(asm.R0, 0),
		asm.Return(),
	}
}

func loadBpfFilter(l netlink.Link, mapFd int, mapIndex ProgMapIndex) error {
	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Type:         ebpf.SchedCLS,
		Instructions: getEntryProgInstructions(mapFd, int32(mapIndex)),
		License:      "ASL2",
	})
	if err != nil {
		return fmt.Errorf("failed to load root BPF prog: %v", err)
	}

	filterAttrs := netlink.FilterAttrs{
		LinkIndex: l.Attrs().Index,
		Parent:    netlink.HANDLE_MIN_EGRESS,
		Handle:    netlink.MakeHandle(0, 1),
		Protocol:  3,
		Priority:  1,
	}
	if mapIndex == IngressMapIndex {
		filterAttrs.Parent = netlink.HANDLE_MIN_INGRESS
	}

	filter := &netlink.BpfFilter{
		FilterAttrs:  filterAttrs,
		Fd:           prog.FD(),
		Name:         bpfFilterName,
		DirectAction: true,
	}

	if err = netlink.FilterAdd(filter); err != nil {
		prog.Close()
		return fmt.Errorf("failed to create cls_bpf filter on link %v: %v", l, err)
	}
	return nil
}

// removeBpfFilter removes the bpf filter for the given direction.
func removeBpfFilter(l netlink.Link, mapIndex ProgMapIndex) error {
	tcDir := uint32(netlink.HANDLE_MIN_EGRESS)
	if mapIndex == IngressMapIndex {
		tcDir = uint32(netlink.HANDLE_MIN_INGRESS)
	}

	filters, err := netlink.FilterList(l, tcDir)
	if err != nil {
		return fmt.Errorf("failed listing TC filters on link %q: %v", l.Attrs().Name, err)
	}

	for _, f := range filters {
		if bpfFilter, ok := f.(*netlink.BpfFilter); ok {
			if bpfFilter.Name == bpfFilterName {
				if err := netlink.FilterDel(f); err != nil {
					log.Debugf("removed bpf filter %q on link %q with direction %d", bpfFilterName, l.Attrs().Name, tcDir)
					return err
				}
			}
		}
	}
	return nil
}

// setupInterfaceInRemoteNs creates a tail call map, renames the netdevice inside
// the target netns and attaches a BPF program to it.
// By default, the tail call map for egress is attached and the ingress is optionally attached.
// The actual programs will be loaded in graftDatapath().
//
// NB: Do not close the returned map before it has been pinned. Otherwise,
// the map will be destroyed.
func setupInterfaceInRemoteNs(netNs ns.NetNS, srcIfName, dstIfName string, ingress bool) (*ebpf.Map, error) {
	rl := unix.Rlimit{
		Cur: unix.RLIM_INFINITY,
		Max: unix.RLIM_INFINITY,
	}

	err := unix.Setrlimit(unix.RLIMIT_MEMLOCK, &rl)
	if err != nil {
		return nil, fmt.Errorf("unable to increase rlimit: %s", err)
	}

	mapSize := 1
	if ingress {
		mapSize = 2
	}
	m, err := ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.ProgramArray,
		KeySize:    4,
		ValueSize:  4,
		MaxEntries: uint32(mapSize),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create root BPF map for %q: %s", dstIfName, err)
	}

	err = netNs.Do(func(_ ns.NetNS) error {
		var err error

		if srcIfName != dstIfName {
			err = link.Rename(srcIfName, dstIfName)
			if err != nil {
				return fmt.Errorf("failed to rename interface from %q to %q: %s", srcIfName, dstIfName, err)
			}
		}

		link, err := netlink.LinkByName(dstIfName)
		if err != nil {
			return fmt.Errorf("failed to lookup link %q: %s", dstIfName, err)
		}

		qdisc := clsactQdisc(link.Attrs().Index)
		if err = netlink.QdiscAdd(qdisc); err != nil {
			return fmt.Errorf("failed to create clsact qdisc on %q: %s", dstIfName, err)
		}

		if err := loadBpfFilter(link, m.FD(), EgressMapIndex); err != nil {
			return fmt.Errorf("failed to load egress bpf filter for interface %q: %v", dstIfName, err)
		}
		if ingress {
			if err := loadBpfFilter(link, m.FD(), IngressMapIndex); err != nil {
				return fmt.Errorf("failed to load ingress bpf filter for interface %q: %v", dstIfName, err)
			}
		}
		return nil
	})
	if err != nil {
		m.Close()
		return nil, err
	}
	return m, nil
}
