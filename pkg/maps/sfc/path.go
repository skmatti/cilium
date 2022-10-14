package sfc

import (
	"fmt"
	"net"
	"unsafe"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/byteorder"
	"github.com/cilium/cilium/pkg/types"
)

const (
	PathMapName      = "google_sfc_path"
	PathMaxEntries   = 16384
	SizeofPathKey    = int(unsafe.Sizeof(PathKey{}))
	SizeofPathEntry  = int(unsafe.Sizeof(PathEntry{}))
	MaxServicePathId = (1 << 24) - 1
)

// PathKey must match 'struct sfc_path_key' in "bpf/lib/google_maps.h".
// +k8s:deepcopy-gen=true
// +k8s:deepcopy-gen:interfaces=github.com/cilium/cilium/pkg/bpf.MapKey
// +k8s:deepcopy-gen:interfaces=github.com/cilium/cilium/pkg/bpf.MapValue
type PathKey struct {
	Path uint32 `align:"path"` // network order
}

func (key *PathKey) GetKeyPtr() unsafe.Pointer   { return unsafe.Pointer(key) }
func (key *PathKey) GetValuePtr() unsafe.Pointer { return unsafe.Pointer(key) }
func (key *PathKey) NewValue() bpf.MapValue      { return &PathEntry{} }

// NewPathKey returns a new PathKey instance from SPI, SI values.
// Returns an error if SPI exceeds 24 bits.
func NewPathKey(servicePathId uint32, serviceIndex uint8) (*PathKey, error) {
	if servicePathId > MaxServicePathId {
		return nil, fmt.Errorf("SPI exceeds 24 bits")
	}
	path := (servicePathId << 8) | uint32(serviceIndex)
	key := &PathKey{Path: byteorder.HostToNetwork32(path)}
	return key, nil
}

func (key *PathKey) ServicePathId() uint32 {
	path := byteorder.NetworkToHost32(key.Path)
	return path >> 8
}

func (key *PathKey) ServiceIndex() uint8 {
	path := byteorder.NetworkToHost32(key.Path)
	return uint8(path)
}

func (key *PathKey) String() string {
	return fmt.Sprintf("(%d, %d)", key.ServicePathId(), key.ServiceIndex())
}

// PathEntry must match 'struct sfc_path_entry' in "bpf/lib/google_maps.h".
// +k8s:deepcopy-gen=true
// +k8s:deepcopy-gen:interfaces=github.com/cilium/cilium/pkg/bpf.MapValue
type PathEntry struct {
	Address types.IPv4 `align:"address"`
}

func (entry *PathEntry) GetValuePtr() unsafe.Pointer { return unsafe.Pointer(entry) }
func (entry *PathEntry) NewValue() bpf.MapValue      { return &PathEntry{} }

func NewPathEntry(ip net.IP) *PathEntry {
	entry := PathEntry{}
	copy(entry.Address[:], ip.To4())
	return &entry
}

func (entry *PathEntry) String() string {
	return entry.Address.String()
}

var PathMap = bpf.NewMap(
	PathMapName,
	bpf.MapTypeHash,
	&PathKey{},
	SizeofPathKey,
	&PathEntry{},
	SizeofPathEntry,
	PathMaxEntries,
	bpf.BPF_F_NO_PREALLOC, 0,
	bpf.ConvertKeyValue,
).WithCache()
