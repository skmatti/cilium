package multinetworking

import (
	"fmt"
	"net"
	"unsafe"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/ebpf"
	"github.com/cilium/cilium/pkg/types"
)

const (
	HostDevRoutingMapName       = "google_host_dev_routing"
	HostDevRoutingMapMaxEntries = 16384
)

var HostDevRoutingMap = bpf.NewMap(
	HostDevRoutingMapName,
	ebpf.LPMTrie,
	&HostDevRoutingKey{},
	&HostDevRoutingEntry{},
	HostDevRoutingMapMaxEntries,
	bpf.BPF_F_NO_PREALLOC,
).WithCache()

// HostDevRoutingKey must match 'struct host_routing_key' in "bpf/lib/google_maps.h".
type HostDevRoutingKey struct {
	// LPMPrefixLen represents the IPAddr mask bits + static bits
	LPMPrefixLen uint32 `align:"lpm_key"`
	// IfIndex represents the interface index of the host's interface.
	IfIndex uint32 `align:"if_index"`
	// IPv4/v6
	Family uint8  `align:"family"`
	Pad0   uint8  `align:"pad0"`
	Pad1   uint16 `align:"pad1"`
	// CIDR represents the network address of the interface
	// Accommodates both IPv6 and IPv4 (in the lowest four bytes)
	CIDR types.IPv6 `align:"$union0"`
}

func (r *HostDevRoutingKey) New() bpf.MapKey { return &HostDevRoutingKey{} }

func (k *HostDevRoutingKey) String() string {
	prefixLen := k.LPMPrefixLen - getStaticPrefixBits()
	switch k.Family {
	case bpf.EndpointKeyIPv4:
		fallthrough
	case bpf.EndpointKeyIPv6:
		ipStr := toIPString(k.Family, k.CIDR)
		return fmt.Sprintf("ifindex=%d, cidr=%s/%d", k.IfIndex, ipStr, prefixLen)
	}
	return "<unknown_family>"
}

func NewHostDevRoutingKey(ifIndex uint32, cidr *net.IPNet) *HostDevRoutingKey {
	result := &HostDevRoutingKey{}

	ones, _ := cidr.Mask.Size()
	result.LPMPrefixLen = getPrefixLen(uint32(ones))
	result.Family, result.CIDR = parse(cidr.IP)
	result.IfIndex = ifIndex
	return result
}

// NextHop must match 'struct host_routing_entry' in "bpf/lib/google_maps.h".
type HostDevRoutingEntry struct {
	// NextHopAddr represents the IP address of next hop.
	// Accommodates both IPv6 and IPv4 (in the lowest four bytes)
	NextHopAddr types.IPv6 `align:"$union0"`
	Family      uint8      `align:"family"`
	Pad3        uint8      `align:"pad3"`
	Pad4        uint16     `align:"pad4"`
}

func (entry *HostDevRoutingEntry) New() bpf.MapValue { return &HostDevRoutingEntry{} }

func (entry *HostDevRoutingEntry) String() string {
	return toIPString(entry.Family, entry.NextHopAddr)
}

func NewHostDevRoutingEntry(ip net.IP) *HostDevRoutingEntry {
	result := &HostDevRoutingEntry{}
	result.Family, result.NextHopAddr = parse(ip)
	return result

}

func toIPString(family uint8, ip types.IPv6) string {
	switch family {
	case bpf.EndpointKeyIPv4:
		return net.IP(ip[:net.IPv4len]).String()
	case bpf.EndpointKeyIPv6:
		return ip.String()
	}
	return "<unknown_family>"
}

func getStaticPrefixBits() uint32 {
	staticMatchSize := unsafe.Sizeof(HostDevRoutingKey{})
	staticMatchSize -= unsafe.Sizeof(HostDevRoutingKey{}.LPMPrefixLen)
	staticMatchSize -= unsafe.Sizeof(HostDevRoutingKey{}.CIDR)
	return uint32(staticMatchSize) * 8
}

func getPrefixLen(prefixBits uint32) uint32 {
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
