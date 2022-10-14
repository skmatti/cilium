package sfc

import (
	"fmt"
	"net"
	"unsafe"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/byteorder"
	"github.com/cilium/cilium/pkg/types"
	"github.com/cilium/cilium/pkg/u8proto"
)

const (
	CIDRMapName     = "google_sfc_cidr"
	CIDRMaxEntries  = 16384
	SizeofCIDRKey   = int(unsafe.Sizeof(CIDRKey{}))
	SizeofCIDREntry = int(unsafe.Sizeof(CIDREntry{}))

	SelectMapName    = "google_sfc_select"
	SelectMaxEntries = 16384
	SizeofSelectKey  = int(unsafe.Sizeof(SelectKey{}))

	// CIDRKeyStaticPrefixBits represents the size in bits of the static
	// prefix part of a CIDR key (i.e. the ep_id and flags).
	CIDRKeyStaticPrefixBits = 32
)

var SupportedProtocols = [...]u8proto.U8proto{u8proto.TCP, u8proto.UDP}

// CIDRKey must match 'struct sfc_cidr_key' in "bpf/lib/google_maps.h".
// +k8s:deepcopy-gen=true
// +k8s:deepcopy-gen:interfaces=github.com/cilium/cilium/pkg/bpf.MapKey
type CIDRKey struct {
	// LPMPrefixLen is full 32 bits of (ep_id, flags) + CIDR's mask bits
	LPMPrefixLen uint32     `align:"lpm_key"`
	EpID         uint16     `align:"ep_id"`
	Flags        uint16     `align:"is_egress"`
	CIDR         types.IPv4 `align:"cidr"`
}

const (
	IsEgress = 1 << iota
	IsDst
)

func (key *CIDRKey) GetKeyPtr() unsafe.Pointer { return unsafe.Pointer(key) }
func (key *CIDRKey) NewValue() bpf.MapValue    { return &CIDREntry{} }

func NewCIDRKey(epID uint16, egress bool, dst bool, cidr net.IPNet) *CIDRKey {
	prefixLen, _ := cidr.Mask.Size()
	key := &CIDRKey{
		LPMPrefixLen: CIDRKeyStaticPrefixBits + uint32(prefixLen),
		EpID:         epID,
	}
	copy(key.CIDR[:], cidr.IP.To4())
	if egress {
		key.Flags |= IsEgress
	}
	if dst {
		key.Flags |= IsDst
	}
	return key
}

func (key *CIDRKey) getDir() string {
	if key.Flags&IsEgress == 0 {
		return "ingress"
	} else {
		return "egress"
	}
}

func (key *CIDRKey) getSrcOrDst() string {
	if key.Flags&IsDst == 0 {
		return "src"
	} else {
		return "dst"
	}
}

func (key *CIDRKey) getCIDR() *net.IPNet {
	return &net.IPNet{
		IP:   key.CIDR.IP(),
		Mask: net.CIDRMask(int(key.LPMPrefixLen-CIDRKeyStaticPrefixBits), net.IPv4len*8),
	}
}

func (key *CIDRKey) String() string {
	return fmt.Sprintf("%d, %s, %s, %s", key.EpID, key.getDir(), key.getSrcOrDst(), key.getCIDR())
}

// CIDREntry must match 'struct sfc_cidr_entry' in "bpf/lib/google_maps.h".
// +k8s:deepcopy-gen=true
// +k8s:deepcopy-gen:interfaces=github.com/cilium/cilium/pkg/bpf.MapValue
type CIDREntry struct {
	PrefixLen uint8 `align:"prefix_len"`
}

func (entry *CIDREntry) GetValuePtr() unsafe.Pointer { return unsafe.Pointer(entry) }
func (entry *CIDREntry) NewValue() bpf.MapValue      { return &CIDREntry{} }

func NewCIDREntry(cidr net.IPNet) *CIDREntry {
	prefixLen, _ := cidr.Mask.Size()
	return &CIDREntry{
		PrefixLen: uint8(prefixLen),
	}
}

func (entry *CIDREntry) String() string {
	return fmt.Sprintf("/%d", entry.PrefixLen)
}

// SelectKey must match 'struct sfc_select_key' in "bpf/lib/google_maps.h".
// +k8s:deepcopy-gen=true
// +k8s:deepcopy-gen:interfaces=github.com/cilium/cilium/pkg/bpf.MapKey
type SelectKey struct {
	EpID          uint16     `align:"ep_id"`
	Port          uint16     `align:"port"` // network order
	SrcCIDR       types.IPv4 `align:"src_cidr"`
	DstCIDR       types.IPv4 `align:"dst_cidr"`
	FromPrefixLen uint8      `align:"src_prefix_len"`
	ToPrefixLen   uint8      `align:"dst_prefix_len"`
	Protocol      uint8      `align:"protocol"`
	Flags         uint8      `align:"is_egress"`
}

func (key *SelectKey) GetKeyPtr() unsafe.Pointer { return unsafe.Pointer(key) }
func (entry *SelectKey) NewValue() bpf.MapValue  { return &PathKey{} }

// NewSelectKey returns a new SelectKey instance.
func NewSelectKey(epID uint16, egress bool, srcCIDR, dstCIDR net.IPNet, port uint16, proto u8proto.U8proto) *SelectKey {
	fromPrefixLen, _ := srcCIDR.Mask.Size()
	toPrefixLen, _ := dstCIDR.Mask.Size()
	key := &SelectKey{
		EpID:          epID,
		Port:          byteorder.HostToNetwork16(port),
		Protocol:      uint8(proto),
		FromPrefixLen: uint8(fromPrefixLen),
		ToPrefixLen:   uint8(toPrefixLen),
	}
	copy(key.SrcCIDR[:], srcCIDR.IP.To4())
	copy(key.DstCIDR[:], dstCIDR.IP.To4())
	if egress {
		key.Flags |= IsEgress
	}
	return key
}

func (key *SelectKey) getDir() string {
	if key.Flags&IsEgress == 0 {
		return "ingress"
	} else {
		return "egress"
	}
}

func (key *SelectKey) getSrcCIDR() *net.IPNet {
	return &net.IPNet{
		IP:   key.SrcCIDR.IP(),
		Mask: net.CIDRMask(int(key.FromPrefixLen), net.IPv4len*8),
	}
}

func (key *SelectKey) getDstCIDR() *net.IPNet {
	return &net.IPNet{
		IP:   key.DstCIDR.IP(),
		Mask: net.CIDRMask(int(key.ToPrefixLen), net.IPv4len*8),
	}
}

func (key *SelectKey) String() string {
	port := byteorder.NetworkToHost16(key.Port)
	proto := u8proto.U8proto(key.Protocol)
	return fmt.Sprintf("%d, %s, %s, %s, %d/%s", key.EpID, key.getDir(), key.getSrcCIDR(), key.getDstCIDR(), port, proto)
}

func SupportedProtocol(proto u8proto.U8proto) bool {
	for _, supportedProto := range SupportedProtocols {
		if supportedProto == proto {
			return true
		}
	}
	return false
}

var CIDRMap = bpf.NewMap(
	CIDRMapName,
	bpf.MapTypeLPMTrie,
	&CIDRKey{},
	SizeofCIDRKey,
	&CIDREntry{},
	SizeofCIDREntry,
	CIDRMaxEntries,
	bpf.BPF_F_NO_PREALLOC, 0,
	bpf.ConvertKeyValue,
).WithCache()

var SelectMap = bpf.NewMap(
	SelectMapName,
	bpf.MapTypeHash,
	&SelectKey{},
	SizeofSelectKey,
	&PathKey{},
	SizeofPathKey,
	SelectMaxEntries,
	bpf.BPF_F_NO_PREALLOC, 0,
	bpf.ConvertKeyValue,
).WithCache()
