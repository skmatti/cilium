package perimetermap

import (
	"fmt"
	"sync"
	"unsafe"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/ebpf"
	perimeterconst "github.com/cilium/cilium/pkg/maps/perimetermap/consts"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/types"
)

var (
	// RedirectEPIPMap4 represents the map of redirect endpoint IPs.
	redirectEPIPMap4 *bpf.Map

	// RedirectEPIDMap4 represents the map of redirect endpoint IDs.
	redirectEPIDMap4 *bpf.Map

	redirectEPIPMap4Once sync.Once
	redirectEPIDMap4Once sync.Once
)

type RedirectEP4ID struct {
	ID uint16
}

func (r *RedirectEP4ID) ToKey() *RedirectEP4IDKey {
	return &RedirectEP4IDKey{Data: *r}
}

func (r *RedirectEP4ID) ToValue() *RedirectEP4IDValue {
	return &RedirectEP4IDValue{Data: *r}
}

type RedirectEP4IDKey struct {
	Data RedirectEP4ID
}

func (k *RedirectEP4IDKey) GetKeyPtr() unsafe.Pointer   { return unsafe.Pointer(k) }
func (k *RedirectEP4IDKey) GetValuePtr() unsafe.Pointer { return unsafe.Pointer(k) }
func (k *RedirectEP4IDKey) New() bpf.MapKey             { return &RedirectEP4IDKey{} }
func (k *RedirectEP4IDKey) String() string {
	return fmt.Sprintf("%d", k.Data.ID)
}

type RedirectEP4IDValue struct {
	Data RedirectEP4ID
}

func (k *RedirectEP4IDValue) GetKeyPtr() unsafe.Pointer   { return unsafe.Pointer(k) }
func (k *RedirectEP4IDValue) GetValuePtr() unsafe.Pointer { return unsafe.Pointer(k) }
func (k *RedirectEP4IDValue) New() bpf.MapValue           { return &RedirectEP4IDValue{} }
func (k *RedirectEP4IDValue) String() string {
	return fmt.Sprintf("%d", k.Data.ID)
}

type RedirectEP4IP struct {
	IP types.IPv4
}

func (r *RedirectEP4IP) ToKey() *RedirectEP4IPKey {
	return &RedirectEP4IPKey{Data: *r}
}

func (r *RedirectEP4IP) ToValue() *RedirectEP4IPValue {
	return &RedirectEP4IPValue{Data: *r}
}

type RedirectEP4IPKey struct {
	Data RedirectEP4IP
}

func (k *RedirectEP4IPKey) GetKeyPtr() unsafe.Pointer   { return unsafe.Pointer(k) }
func (k *RedirectEP4IPKey) GetValuePtr() unsafe.Pointer { return unsafe.Pointer(k) }
func (k *RedirectEP4IPKey) New() bpf.MapKey             { return &RedirectEP4IPKey{} }
func (k *RedirectEP4IPKey) String() string {
	return k.Data.IP.String()
}

type RedirectEP4IPValue struct {
	Data RedirectEP4IP
}

func (k *RedirectEP4IPValue) GetKeyPtr() unsafe.Pointer   { return unsafe.Pointer(k) }
func (k *RedirectEP4IPValue) GetValuePtr() unsafe.Pointer { return unsafe.Pointer(k) }
func (k *RedirectEP4IPValue) New() bpf.MapValue           { return &RedirectEP4IPValue{} }
func (k *RedirectEP4IPValue) String() string {
	return k.Data.IP.String()
}

func InitRedirectEPIPMap4() *bpf.Map {
	redirectEPIPMap4Once.Do(func() {
		redirectEPIPMap4 = bpf.NewMap(perimeterconst.RedirectEPIPMap4Name,
			ebpf.Hash,
			&RedirectEP4IDKey{},
			&RedirectEP4IPValue{},
			perimeterconst.RedirectEPMaxEntries,
			0,
		).WithCache().WithPressureMetric().
			WithEvents(option.Config.GetEventBufferConfig(perimeterconst.RedirectEPIPMap4Name))
	})
	return redirectEPIPMap4
}

func InitRedirectEPIDMap4() *bpf.Map {
	redirectEPIDMap4Once.Do(func() {
		redirectEPIDMap4 = bpf.NewMap(perimeterconst.RedirectEPIDMap4Name,
			ebpf.Hash,
			&RedirectEP4IPKey{},
			&RedirectEP4IDValue{},
			perimeterconst.RedirectEPMaxEntries,
			0,
		).WithCache().WithPressureMetric().
			WithEvents(option.Config.GetEventBufferConfig(perimeterconst.RedirectEPIDMap4Name))
	})
	return redirectEPIDMap4
}
