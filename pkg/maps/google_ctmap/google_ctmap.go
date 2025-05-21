package google_ctmap

import (
	"fmt"
	"sync"
	"unsafe"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/tuple"
	"github.com/cilium/cilium/pkg/types"
	ciliumebpf "github.com/cilium/ebpf"
)

const (
	// GoogleCtMapName is the name of the BPF map used for Google CT (Connection Tracking).
	GoogleCtMapName          = "google_ctmap_v4"
	EgressNatFlagMask uint32 = 1 << 0
	ElbFlagMask       uint32 = 1 << 1
)

var (
	googleCtMap     *bpf.Map
	googleCtMapOnce sync.Once
)

// Google CtMap reuses the Cilium IPv4 conntrack map key
type GoogleCtMapKey4 struct {
	tuple.TupleKey4Global
}

func (k *GoogleCtMapKey4) GetKeyPtr() unsafe.Pointer { return unsafe.Pointer(k) }
func (k *GoogleCtMapKey4) New() bpf.MapKey           { return &GoogleCtMapKey4{} }
func (k *GoogleCtMapKey4) String() string {
	return fmt.Sprintf("%s:%d --> %s:%d, %d, %d", k.SourceAddr, k.SourcePort, k.DestAddr, k.DestPort, k.NextHeader, k.Flags)
}

// GoogleCtMapEntry holds one IPv4 address and a field to hold flags
// which are used to determine the context in which the IP Address
// is to be used. The flags field has reserved padding to account for
// future use cases.
type GoogleCtMapEntry4 struct {
	Ip4Addr types.IPv4 `align:"ip4_addr"`
	Flags   uint32     `align:"egress_nat"`
}

func (v *GoogleCtMapEntry4) GetValuePtr() unsafe.Pointer { return unsafe.Pointer(v) }
func (v *GoogleCtMapEntry4) New() bpf.MapValue           { return &GoogleCtMapEntry4{} }
func (v *GoogleCtMapEntry4) String() string {
	return fmt.Sprintf("IP: %s, Flags: %d", v.Ip4Addr, v.Flags)
}

// InitGoogleCtMap initializes the Google CT BPF map.
func InitGoogleCtMap() *bpf.Map {
	googleCtMap = bpf.NewMap(GoogleCtMapName,
		ciliumebpf.LRUHash,
		&GoogleCtMapKey4{},
		&GoogleCtMapEntry4{},
		option.Config.CTMapEntriesGlobalAny+option.Config.CTMapEntriesGlobalTCP,
		0,
	).WithPressureMetric()
	return googleCtMap
}

// EgressNatEnabled checks if the EgressNatFlag is set in the Flags field.
func (e *GoogleCtMapEntry4) EgressNatEnabled() bool {
	return (e.Flags & EgressNatFlagMask) != 0
}

// ElbEnabled checks if the ElbFlag is set in the Flags field.
func (e *GoogleCtMapEntry4) ElbEnabled() bool {
	return (e.Flags & ElbFlagMask) != 0
}

// SetEgressNatFlag sets or clears the EgressNatFlag in the Flags field.
func (e *GoogleCtMapEntry4) SetEgressNatFlag(set bool) {
	if set {
		e.Flags |= EgressNatFlagMask
	} else {
		e.Flags &^= EgressNatFlagMask
	}
}

// SetElbFlag sets or clears the ElbFlag in the Flags field.
func (e *GoogleCtMapEntry4) SetElbFlag(set bool) {
	if set {
		e.Flags |= ElbFlagMask
	} else {
		e.Flags &^= ElbFlagMask
	}
}
