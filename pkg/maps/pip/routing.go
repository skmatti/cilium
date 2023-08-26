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

func toIPString(family uint8, ip types.IPv6) string {
	switch family {
	case bpf.EndpointKeyIPv4:
		return net.IP(ip[:net.IPv4len]).String()
	case bpf.EndpointKeyIPv6:
		return ip.String()
	}
	return "<unknown_family>"
}

func (k *CIDRKey) String() string {
	prefixLen := k.LPMPrefixLen - getStaticPrefixBits()
	switch k.Family {
	case bpf.EndpointKeyIPv4:
		fallthrough
	case bpf.EndpointKeyIPv6:
		ipStr := toIPString(k.Family, k.CIDR)
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

func NewCIDRKey(cidr *net.IPNet) *CIDRKey {
	result := &CIDRKey{}

	ones, _ := cidr.Mask.Size()
	result.LPMPrefixLen = getStaticPrefixBits() + uint32(ones)
	result.Family, result.CIDR = parse(cidr.IP)
	return result
}

// RoutingEntry must match 'struct pip_routing_entry' in "bpf/lib/google_maps.h".
// +k8s:deepcopy-gen=true
// +k8s:deepcopy-gen:interfaces=github.com/cilium/cilium/pkg/bpf.MapValue
type RoutingEntry struct {
	// IP of the endpoint.
	// represents both IPv6 and IPv4 (in the lowest four bytes)
	EndpointIP types.IPv6 `align:"$union0"`
	Family     uint8      `align:"family"`
	Pad0       uint8      `align:"pad3"`
	Pad1       uint16     `align:"pad4"`
}

func NewRoutingEntry(ip net.IP) *RoutingEntry {
	result := &RoutingEntry{}
	result.Family, result.EndpointIP = parse(ip)
	return result

}

func (entry *RoutingEntry) GetValuePtr() unsafe.Pointer { return unsafe.Pointer(entry) }

func (entry *RoutingEntry) NewValue() bpf.MapValue { return &RoutingEntry{} }

func (entry *RoutingEntry) String() string {
	return toIPString(entry.Family, entry.EndpointIP)
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
