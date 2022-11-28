package sfc

import (
	"fmt"
	"math"
	"strings"
	"unsafe"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/byteorder"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/types"
	"github.com/cilium/cilium/pkg/u8proto"
	"github.com/sirupsen/logrus"
)

const (
	FlowMapAny4Name = "google_sfc_flow_any4"
)

var log = logging.DefaultLogger.WithField(logfields.LogSubsys, "sfc")

// FlowKey4 is the key to FlowMapAny4.
// +k8s:deepcopy-gen=true
// +k8s:deepcopy-gen:interfaces=github.com/cilium/cilium/pkg/bpf.MapKey
type FlowKey4 struct {
	SourceAddr types.IPv4      `align:"saddr"`
	DestAddr   types.IPv4      `align:"daddr"`
	SourcePort uint16          `align:"sport"`
	DestPort   uint16          `align:"dport"`
	EpID       uint16          `align:"ep_id"`
	NextHeader u8proto.U8proto `align:"nexthdr"`
	Pad        uint8           `align:"pad"`
}

// NewValue creates a new bpf.MapValue.
func (k *FlowKey4) NewValue() bpf.MapValue { return &FlowEntry4{} }

func (k *FlowKey4) String() string {
	return fmt.Sprintf("%d, %s:%d --> %s:%d, %s", k.EpID, k.SourceAddr, byteorder.NetworkToHost16(k.SourcePort), k.DestAddr, byteorder.NetworkToHost16(k.DestPort), k.NextHeader.String())
}

// GetKeyPtr returns the unsafe.Pointer for k.
func (k *FlowKey4) GetKeyPtr() unsafe.Pointer { return unsafe.Pointer(k) }

// FlowEntry4 represents an entry in the flow tracking table.
// +k8s:deepcopy-gen=true
// +k8s:deepcopy-gen:interfaces=github.com/cilium/cilium/pkg/bpf.MapValue
type FlowEntry4 struct {
	Path               uint32     `align:"path"`
	PreviousHopAddress types.IPv4 `align:"previous_hop_addr"`
	Lifetime           uint32     `align:"lifetime"`
	Flags              uint16     `align:"rx_closing"`
}

const (
	RxClosing = 1 << iota
	TxClosing
	SeenNonSyn
	SeenRxSyn
	SeenTxSyn
	MaxFlags
)

// GetValuePtr returns the unsafe.Pointer for s.
func (v *FlowEntry4) GetValuePtr() unsafe.Pointer { return unsafe.Pointer(v) }

func (v *FlowEntry4) flagsString() string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("Flags=%#04x [ ", v.Flags))
	if (v.Flags & RxClosing) != 0 {
		sb.WriteString("RxClosing ")
	}
	if (v.Flags & TxClosing) != 0 {
		sb.WriteString("TxClosing ")
	}
	if (v.Flags & SeenNonSyn) != 0 {
		sb.WriteString("SeenNonSyn ")
	}
	if (v.Flags & SeenRxSyn) != 0 {
		sb.WriteString("SeenRxSyn ")
	}
	if (v.Flags & SeenTxSyn) != 0 {
		sb.WriteString("SeenTxSyn ")
	}

	unknownFlags := v.Flags
	unknownFlags &^= MaxFlags - 1
	if unknownFlags != 0 {
		sb.WriteString(fmt.Sprintf("Unknown=%#04x ", unknownFlags))
	}
	sb.WriteString("]")
	return sb.String()
}

// StringWithTimeDiff returns a string with time remaining before expiration.
func (v *FlowEntry4) StringWithTimeDiff(toRemSecs func(uint32) string) string {
	var timeDiff string
	if toRemSecs != nil {
		timeDiff = fmt.Sprintf(" (%s)", toRemSecs(v.Lifetime))
	} else {
		timeDiff = ""
	}

	spi, si := extractSPISI(v.Path)
	return fmt.Sprintf("SPI=%d SI=%d PreviousHopAddress=%s expires=%d%s  %s\n",
		spi, si,
		v.PreviousHopAddress.String(),
		v.Lifetime,
		timeDiff,
		v.flagsString())
}

// String returns the readable format
func (v *FlowEntry4) String() string {
	return v.StringWithTimeDiff(nil)
}

var FlowMapAny4 *bpf.Map

func InitFlowMap(maxEntries int) {
	FlowMapAny4 = bpf.NewMap(
		FlowMapAny4Name,
		bpf.MapTypeLRUHash,
		&FlowKey4{},
		int(unsafe.Sizeof(FlowKey4{})),
		&FlowEntry4{},
		int(unsafe.Sizeof(FlowEntry4{})),
		maxEntries,
		0, 0,
		bpf.ConvertKeyValue,
	)
}

// DumpEntriesWithTimeDiff iterates through Map m and writes the values of the
// entries in m to a string. If clockSource is not nil, it uses it to
// compute the time difference of each entry from now and prints that too.
func DumpEntriesWithTimeDiff(m *bpf.Map, clockSource *models.ClockSource) (string, error) {
	var toRemSecs func(uint32) string

	if clockSource == nil {
		toRemSecs = nil
	} else if clockSource.Mode == models.ClockSourceModeKtime {
		now, err := bpf.GetMtime()
		if err != nil {
			return "", err
		}
		now = now / 1000000000
		toRemSecs = func(t uint32) string {
			diff := int64(t) - int64(now)
			return fmt.Sprintf("remaining: %d sec(s)", diff)
		}
	} else if clockSource.Mode == models.ClockSourceModeJiffies {
		now, err := bpf.GetJtime()
		if err != nil {
			return "", err
		}
		if clockSource.Hertz == 0 {
			return "", fmt.Errorf("invalid clock Hertz value (0)")
		}
		toRemSecs = func(t uint32) string {
			diff := int64(t) - int64(now)
			diff = diff << 8
			diff = diff / int64(clockSource.Hertz)
			return fmt.Sprintf("remaining: %d sec(s)", diff)
		}
	} else {
		return "", fmt.Errorf("unknown clock source: %s", clockSource.Mode)
	}

	var sb strings.Builder
	cb := func(k bpf.MapKey, v bpf.MapValue) {
		// No need to deep copy as the values are used to create new strings
		sb.WriteString(k.String() + "\t")
		value := v.(*FlowEntry4)
		sb.WriteString(value.StringWithTimeDiff(toRemSecs))
	}
	// DumpWithCallback() must be called before sb.String().
	err := m.DumpWithCallback(cb)
	if err != nil {
		return "", err
	}
	return sb.String(), err
}

var flowGCLock lock.Mutex

func now() uint32 {
	var t uint64
	if option.Config.ClockSource == option.ClockSourceKtime {
		t, _ = bpf.GetMtime()
		t = t / 1000000000
	} else {
		t, _ = bpf.GetJtime()
	}
	return uint32(t)
}

func doGC(now uint32) uint32 {
	var deleted uint32
	callback := func(key bpf.MapKey, value bpf.MapValue) {
		entry := value.(*FlowEntry4)
		if entry.Lifetime < now {
			if err := FlowMapAny4.Delete(key); err != nil {
				log.WithError(err).WithField(logfields.Key, key.String()).Error("Unable to delete sfc flow entry")
			} else {
				deleted++
			}
		}
	}
	flowGCLock.Lock()
	defer flowGCLock.Unlock()

	if err := FlowMapAny4.DumpReliablyWithCallback(callback, bpf.NewDumpStats(FlowMapAny4)); err != nil {
		log.WithError(err).Error("failed to dump FlowMapAny4")
	}
	return deleted
}

// FlushFlow removes all entries from FlowMapAny4.
// Returns the number of entries removed.
func FlushFlow() uint32 {
	return doGC(math.MaxUint32)
}

// FlowGC removes all expired entries from FlowMapAny4.
// Returns the ratio of deleted entries.
func FlowGC() float64 {
	if !option.Config.EnableGoogleServiceSteering {
		return 0.0
	}

	deleted := doGC(now())
	log.WithFields(logrus.Fields{
		"count": deleted,
	}).Debug("Deleted entries from sfc flow map")
	return float64(deleted) / float64(FlowMapAny4.MapInfo.MaxEntries)
}
