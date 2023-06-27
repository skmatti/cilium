package pip

import (
	"fmt"
	"net"
	"unsafe"

	bpf "github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/types"
)

const (
	RoutingMapName     = "google_pip_route"
	RoutingMaxEntries  = 16384
	SizeofCIDRKey      = int(unsafe.Sizeof(CIDRKey{}))
	SizeofRoutingEntry = int(unsafe.Sizeof(RoutingEntry{}))
)

// CIDRKey must match 'struct pip_cidr_key' in "bpf/lib/google_maps.h".
// +k8s:deepcopy-gen=true
// +k8s:deepcopy-gen:interfaces=github.com/cilium/cilium/pkg/bpf.MapKey
type CIDRKey struct {
	// LPMPrefixLen represents the CIDR mask bits
	LPMPrefixLen uint32 `align:"lpm_key"`
	// IPv4/v6
	Family uint8  `align:"family"`
	Pad0   uint8  `align:"pad0"`
	Pad1   uint16 `align:"pad1"`
	// CIDR represents both IPv6 and IPv4 (in the lowest four bytes)
	CIDR types.IPv6 `align:"$union0"`
}

func (key *CIDRKey) GetKeyPtr() unsafe.Pointer { return unsafe.Pointer(key) }

func (key *CIDRKey) GetValuePtr() unsafe.Pointer { return unsafe.Pointer(key) }

func (key *CIDRKey) NewValue() bpf.MapValue { return &RoutingEntry{} }

func (k *CIDRKey) String() string {
	prefixLen := k.LPMPrefixLen - getStaticPrefixBits()
	switch k.Family {
	case bpf.EndpointKeyIPv4:
		ipStr := net.IP(k.CIDR[:net.IPv4len]).String()
		return fmt.Sprintf("%s/%d", ipStr, prefixLen)
	case bpf.EndpointKeyIPv6:
		ipStr := k.CIDR.String()
		return fmt.Sprintf("%s/%d", ipStr, prefixLen)
	}
	return "<unknown_family>"
}

func getStaticPrefixBits() uint32 {
	staticMatchSize := unsafe.Sizeof(CIDRKey{})
	staticMatchSize -= unsafe.Sizeof(CIDRKey{}.LPMPrefixLen)
	staticMatchSize -= unsafe.Sizeof(CIDRKey{}.CIDR)
	return uint32(staticMatchSize) * 8
}

func getPrefixLen(prefixBits int) uint32 {
	return getStaticPrefixBits() + uint32(prefixBits)
}

func NewCIDRKey(cidr *net.IPNet) *CIDRKey {
	result := &CIDRKey{}

	ones, _ := cidr.Mask.Size()
	result.LPMPrefixLen = getStaticPrefixBits() + uint32(ones)
	if ip4 := cidr.IP.To4(); ip4 != nil {
		result.Family = bpf.EndpointKeyIPv4
		copy(result.CIDR[:], ip4)
	} else {
		result.Family = bpf.EndpointKeyIPv6
		copy(result.CIDR[:], cidr.IP)
	}

	return result
}

// RoutingEntry must match 'struct pip_routing_entry' in "bpf/lib/google_maps.h".
// +k8s:deepcopy-gen=true
// +k8s:deepcopy-gen:interfaces=github.com/cilium/cilium/pkg/bpf.MapValue
type RoutingEntry struct {
	// index of an L3 host-side veth interface on pod to which pip points to.
	IfIndex    uint32 `align:"ifindex"`
	EndpointID uint16 `align:"ep_id"`
}

func (entry *RoutingEntry) GetValuePtr() unsafe.Pointer { return unsafe.Pointer(entry) }

func (entry *RoutingEntry) NewValue() bpf.MapValue { return &RoutingEntry{} }

func (entry *RoutingEntry) String() string {
	return fmt.Sprintf("ep_id=%-5d ifindex=%-3d", entry.EndpointID, entry.IfIndex)
}

var RoutingMap = bpf.NewMap(
	RoutingMapName,
	bpf.MapTypeLPMTrie,
	&CIDRKey{},
	SizeofCIDRKey,
	&RoutingEntry{},
	SizeofRoutingEntry,
	RoutingMaxEntries,
	bpf.BPF_F_NO_PREALLOC, 0,
	bpf.ConvertKeyValue,
).WithCache()
