package multinicdev

import (
	"fmt"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/mac"
	"github.com/cilium/ebpf"
)

const (
	MapName    = "google_multi_nic_dev"
	MaxEntries = 16384
)

// MAC is to enforce the size of the MAC address.
type MAC [6]byte

// convert converts a mac.MAC into the 6 byte array.
func convert(m mac.MAC) (MAC, error) {
	if len(m) != len(MAC{}) {
		return MAC{}, fmt.Errorf("Only 6 bytes MAC address is supported: %s", m)
	}
	return MAC{m[0], m[1], m[2], m[3], m[4], m[5]}, nil
}

func ParseMAC(s string) (MAC, error) {
	m, err := mac.ParseMAC(s)
	if err != nil {
		return MAC{}, fmt.Errorf("unable to parse MAC %q: %v", s, err)
	}
	return convert(m)
}

func (m MAC) String() string {
	return mac.MAC{m[0], m[1], m[2], m[3], m[4], m[5]}.String()
}

// DeepCopyInto is a deepcopy function, copying the receiver, writing into out. in must be non-nil.
// This is to allow deepcopy-gen to work on the Key struct.
func (m *MAC) DeepCopyInto(out *MAC) {
	copy(out[:], m[:])
}

// +k8s:deepcopy-gen=true
// +k8s:deepcopy-gen:interfaces=github.com/cilium/cilium/pkg/bpf.MapKey
type Key struct {
	MAC MAC `align:"mac"`
}

func (k *Key) String() string {
	return fmt.Sprintf("%s", k.MAC)
}

func (k *Key) New() bpf.MapKey {
	return &Key{}
}

// NewKey returns a new Key instance
func NewKey(m MAC) Key {
	ret := Key{
		MAC: m,
	}
	return ret
}

// MultiNICDevInfo implements the bpf.MapValue interface. It contains the
// information about the multi-nic device.
// +k8s:deepcopy-gen=true
// +k8s:deepcopy-gen:interfaces=github.com/cilium/cilium/pkg/bpf.MapValue
type MultiNICDevInfo struct {
	IfIndex    uint32 `align:"ifindex"`
	EndpointID uint16 `align:"ep_id"`
	Pad        uint16 `align:"pad"`
}

func (v *MultiNICDevInfo) String() string {
	return fmt.Sprintf("ep_id=%-5d ifindex=%-3d", v.EndpointID, v.IfIndex)
}

func (v *MultiNICDevInfo) New() bpf.MapValue {
	return &MultiNICDevInfo{}
}

var Map = bpf.NewMap(
	MapName,
	ebpf.Hash,
	&Key{},
	&MultiNICDevInfo{},
	MaxEntries,
	bpf.BPF_F_NO_PREALLOC,
).WithCache()

// DeleteEntry deletes a single map entry
func DeleteEntry(s string) error {
	m, err := ParseMAC(s)
	if err != nil {
		return err
	}
	key := NewKey(m)
	return Map.Delete(&key)
}

// DumpToMap dumps the contents of the multinicdev into a map and returns it
func DumpToMap() (map[string]*MultiNICDevInfo, error) {
	m := map[string]*MultiNICDevInfo{}
	callback := func(key bpf.MapKey, value bpf.MapValue) {
		if info, ok := value.(*MultiNICDevInfo); ok {
			if devKey, ok := key.(*Key); ok {
				m[devKey.MAC.String()] = info
			}
		}
	}

	if err := Map.DumpWithCallback(callback); err != nil {
		return nil, fmt.Errorf("unable to read BPF multinicdev list: %s", err)
	}

	return m, nil
}

type endpoint interface {
	LXCMac() mac.MAC
	GetParentDevIndex() int
	GetID() uint64
	IsMultiNIC() bool
}

func endpointKey(e endpoint) (*Key, error) {
	m, err := convert(e.LXCMac())
	if err != nil {
		return nil, err
	}
	key := NewKey(m)
	return &key, nil
}

// AddEndpointToMap updates the BPF map with the endpoint information
func AddEndpointToMap(e endpoint) error {
	if !e.IsMultiNIC() {
		return nil
	}
	key, err := endpointKey(e)
	if err != nil {
		return err
	}
	value := &MultiNICDevInfo{
		EndpointID: uint16(e.GetID()),
		IfIndex:    uint32(e.GetParentDevIndex()),
	}
	if err := Map.Update(key, value); err != nil {
		return fmt.Errorf("error updating multinicdev map: %v", err)
	}
	return nil
}

// DeleteEndpointFromMap removes the entry from the Map related to the endpoint.
func DeleteEndpointFromMap(e endpoint) error {
	if !e.IsMultiNIC() {
		return nil
	}
	key, err := endpointKey(e)
	if err != nil {
		return err
	}
	if err := Map.Delete(key); err != nil {
		return fmt.Errorf("failed to delete multinicdev entry for endpoint (%s %d): %v", e.LXCMac(), e.GetID(), err)
	}
	return nil
}
