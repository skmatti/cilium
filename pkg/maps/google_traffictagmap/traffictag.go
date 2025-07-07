package google_traffictagmap

import (
	"errors"
	"fmt"
	"unsafe"

	"github.com/cilium/cilium/pkg/ebpf"
	"github.com/cilium/cilium/pkg/types"
)

var (
	TrafficTagMap *trafficTagMap
)

const (
	MaxEntries = 1024

	// Name is the canonical name for the TrafficTag map on the filesystem.
	Name = "google_traffic_tag_map"
)

// Key implements the bpf.MapKey interface.
//
// Must be in sync with struct google_traffic_tag_key in <bpf/lib/google_ip_options.h>
// +k8s:deepcopy-gen=true
// +k8s:deepcopy-gen:interfaces=github.com/cilium/cilium/pkg/bpf.MapKey
type TrafficTagKey struct {
	SourceIP   types.IPv4 `align:"source_ip"`
	DestIP     types.IPv4 `align:"dest_ip"`
	DestPort   uint16     `align:"dest_port"`
	SourcePort uint16     `align:"src_port"`
}

type TrafficTagValue struct {
	TraceID uint16 `align:"trace_id"`
}

type trafficTagMap struct {
	*ebpf.Map
}

func InitTrafficTagMap(create bool) error {
	var m *ebpf.Map

	if create {
		m = ebpf.NewMap(
			&ebpf.MapSpec{
				Name:       Name,
				Type:       ebpf.Hash,
				KeySize:    uint32(unsafe.Sizeof(TrafficTagKey{})),
				ValueSize:  uint32(unsafe.Sizeof(TrafficTagValue{})),
				MaxEntries: uint32(MaxEntries),
				Pinning:    ebpf.PinByName,
			},
		)

		if err := m.OpenOrCreate(); err != nil {
			return err
		}
	} else {
		var err error

		if m, err = ebpf.LoadRegisterMap(Name); err != nil {
			return err
		}
	}

	TrafficTagMap = &trafficTagMap{
		m,
	}
	return nil
}

func NewTrafficTagKey(k PacketTaggingKey) (TrafficTagKey, error) {
	key := TrafficTagKey{}

	netSourceIP, err := k.NetworkSourceIP()
	if err != nil {
		return key, err
	}
	netDestIP, err := k.NetworkDestinationIP()
	if err != nil {
		return key, err
	}

	copy(key.SourceIP[:], netSourceIP.To4())
	copy(key.DestIP[:], netDestIP.To4())
	key.DestPort = k.DestinationPort
	key.SourcePort = k.SourcePort
	return key, nil
}

func NewTrafficTagValue(v PacketTaggingValue) TrafficTagValue {
	value := TrafficTagValue{}
	value.TraceID = v.TraceID
	return value
}

func NewPacketTagValue(v TrafficTagValue) PacketTaggingValue {
	return PacketTaggingValue{
		TraceID: v.TraceID,
	}
}

func (m *trafficTagMap) Lookup(k PacketTaggingKey) (PacketTaggingValue, error) {
	val := TrafficTagValue{}
	key, err := NewTrafficTagKey(k)
	if err != nil {
		return NewPacketTagValue(val), err
	}
	err = m.Map.Lookup(&key, &val)
	return NewPacketTagValue(val), err
}

func (m *trafficTagMap) Update(k PacketTaggingKey, v PacketTaggingValue) error {
	key, err := NewTrafficTagKey(k)
	if err != nil {
		return err
	}
	val := NewTrafficTagValue(v)
	return m.Map.Update(key, val, 0)
}

func (m *trafficTagMap) Delete(k PacketTaggingKey) error {
	key, err := NewTrafficTagKey(k)
	if err != nil {
		return err
	}
	return m.Map.Delete(key)
}

func (m *trafficTagMap) EmptyMap() error {
	iter := m.Iterate()
	var key TrafficTagKey
	var value TrafficTagValue
	for iter.Next(&key, &value) {
		if err := m.Map.Delete(&key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return fmt.Errorf("error deleting key from map: %w", err)
		}
	}
	if err := iter.Err(); err != nil {
		return fmt.Errorf("error during map iteration: %w", err)
	}
	return nil
}
