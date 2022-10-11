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
	SelectMapName     = "google_sfc_select"
	SelectMaxEntries  = 16384
	SizeofSelectKey   = int(unsafe.Sizeof(SelectKey{}))
	SizeofSelectEntry = int(unsafe.Sizeof(SelectEntry{}))

	// SelectKeyStaticPrefixBits represents the size in bits of the static
	// prefix part of a SelectKey
	SelectKeyStaticPrefixBits = 64
)

const (
	IsEgress = 1 << iota
)

var (
	SupportedProtocols = [...]u8proto.U8proto{u8proto.TCP, u8proto.UDP}
	AllIPv4            = net.IPNet{IP: net.IPv4zero, Mask: net.CIDRMask(0, net.IPv4len*8)}
)

// SelectKey must match 'struct sfc_select_key' in "bpf/lib/google_maps.h".
// +k8s:deepcopy-gen=true
// +k8s:deepcopy-gen:interfaces=github.com/cilium/cilium/pkg/bpf.MapKey
type SelectKey struct {
	LPMPrefixLen uint32 `align:"lpm_key"`
	EpID         uint16 `align:"ep_id"`
	Family       uint8  `align:"family"`
	Flags        uint8  `align:"is_egress"`
	Port         uint16 `align:"port"` // network order
	Protocol     uint8  `align:"protocol"`
	Pad1         uint8  `align:"pad1"`
	// CIDR represents both IPv6 and IPv4 (in the lowest four bytes)
	CIDR types.IPv6 `align:"$union0"`
}

// SelectEntry must match 'struct sfc_select_entry' in "bpf/lib/google_maps.h".
// +k8s:deepcopy-gen=true
// +k8s:deepcopy-gen:interfaces=github.com/cilium/cilium/pkg/bpf.MapValue
type SelectEntry struct {
	PrefixLen uint8  `align:"prefix_len"`
	Pad0      uint8  `align:"pad0"`
	Pad1      uint16 `align:"pad1"`
	Path      uint32 `align:"path"` // network order
}

func (key *SelectKey) GetKeyPtr() unsafe.Pointer       { return unsafe.Pointer(key) }
func (entry *SelectKey) NewValue() bpf.MapValue        { return &PathKey{} }
func (entry *SelectEntry) GetValuePtr() unsafe.Pointer { return unsafe.Pointer(entry) }
func (entry *SelectEntry) NewValue() bpf.MapValue      { return &SelectEntry{} }

// NewSelectKey returns a new SelectKey instance.
func NewSelectKey(epID uint16, egress bool, port uint16, proto u8proto.U8proto, cidr net.IPNet) *SelectKey {
	prefixLen, _ := cidr.Mask.Size()

	key := &SelectKey{
		LPMPrefixLen: SelectKeyStaticPrefixBits + uint32(prefixLen),
		EpID:         epID,
		Family:       bpf.EndpointKeyIPv4,
		Port:         byteorder.HostToNetwork16(port),
		Protocol:     uint8(proto),
	}
	key.Family, key.CIDR = parse(cidr.IP)
	if egress {
		key.Flags |= IsEgress
	}
	return key
}

func (key *SelectKey) IsEgress() bool {
	return key.Flags&IsEgress == 1
}

func (key *SelectKey) getDir() string {
	if key.IsEgress() {
		return "egress"
	} else {
		return "ingress"
	}
}

func (key *SelectKey) GetCIDR() *net.IPNet {
	ipLen := net.IPv4len
	if key.Family == bpf.EndpointKeyIPv6 {
		ipLen = net.IPv6len
	}
	return &net.IPNet{
		IP:   net.IP(key.CIDR[:ipLen]),
		Mask: net.CIDRMask(int(key.LPMPrefixLen-SelectKeyStaticPrefixBits), ipLen*8),
	}
}

func (key *SelectKey) String() string {
	port := byteorder.NetworkToHost16(key.Port)
	proto := u8proto.U8proto(key.Protocol)
	return fmt.Sprintf("%d, %s, %d/%s, %s", key.EpID, key.getDir(), port, proto, key.GetCIDR())
}

// NewSelectEntry returns a new SelectEntry instance from prefix length and (SPI, SI).
// Returns an error if SPI exceeds the maximum value.
func NewSelectEntry(servicePathId uint32, serviceIndex uint8, cidr net.IPNet) (*SelectEntry, error) {
	prefixLen, _ := cidr.Mask.Size()
	if servicePathId > MaxServicePathId {
		return nil, fmt.Errorf("SPI %d exceeds max value %d", servicePathId, MaxServicePathId)
	}
	path := (servicePathId << 8) | uint32(serviceIndex)
	key := &SelectEntry{Path: byteorder.HostToNetwork32(path), PrefixLen: uint8(prefixLen)}
	return key, nil
}

func (entry *SelectEntry) PathKey() PathKey {
	return PathKey{Path: entry.Path}
}

func (entry *SelectEntry) String() string {
	path := entry.PathKey()
	return fmt.Sprintf("/%d %s", entry.PrefixLen, &path)
}

func SupportedProtocol(proto u8proto.U8proto) bool {
	for _, supportedProto := range SupportedProtocols {
		if supportedProto == proto {
			return true
		}
	}
	return false
}

func parse(ip net.IP) (uint8, types.IPv6) {
	var result types.IPv6
	var family uint8
	if ip4 := ip.To4(); ip4 != nil {
		family = bpf.EndpointKeyIPv4
		copy(result[:], ip4)
	} else {
		family = bpf.EndpointKeyIPv6
		copy(result[:], ip)
	}
	return family, result
}

var SelectMap = bpf.NewMap(
	SelectMapName,
	bpf.MapTypeLPMTrie,
	&SelectKey{},
	SizeofSelectKey,
	&SelectEntry{},
	SizeofSelectEntry,
	SelectMaxEntries,
	bpf.BPF_F_NO_PREALLOC, 0,
	bpf.ConvertKeyValue,
).WithCache()
