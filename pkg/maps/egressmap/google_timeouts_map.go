package egressmap

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/datapath/linux/config/defines"
	"github.com/cilium/cilium/pkg/ebpf"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/hive/cell"
)

/*
 * EgressTimeoutsMap - Per-endpoint connection timeouts for egress NAT.
 *
 * This map stores custom timeout values for different connection states
 * in egress NAT scenarios.
 *
 * EgressTimeoutsMap is a subset of EgressPolicyMap, and
 * only contains entries for endpoints whose corresponding
 * CiliumEgressGatewayPolicy defines custom timeouts. If a timeout
 * value is not specified for a given endpoint, or if there is no
 * corresponding entry in EgressTimeoutsMap for the endpoint,
 * the default timeout value from cilium-config will be used.
 */
const (
	EgressTimeoutsMapName = "cilium_egress_timeouts_v4"

	// EgressTimeoutsStaticPrefixBits represents the size in bits of the static
	// prefix part of an egress timeouts key (i.e. the source IP).
	EgressTimeoutsStaticPrefixBits = PolicyStaticPrefixBits
)

type ConnectionTimeouts struct {
	BpfCtTimeoutRegularAny    uint32
	BpfCtTimeoutRegularTcp    uint32
	BpfCtTimeoutRegularTcpFin uint32
	BpfCtTimeoutRegularTcpSyn uint32
}

func (ct ConnectionTimeouts) String() string {
	buffer := []string{}
	if ct.BpfCtTimeoutRegularAny != 0 {
		buffer = append(buffer, fmt.Sprintf("BpfCtTimeoutRegularAny: %d", ct.BpfCtTimeoutRegularAny))
	}
	if ct.BpfCtTimeoutRegularTcp != 0 {
		buffer = append(buffer, fmt.Sprintf("BpfCtTimeoutRegularTcp: %d", ct.BpfCtTimeoutRegularTcp))
	}
	if ct.BpfCtTimeoutRegularTcpFin != 0 {
		buffer = append(buffer, fmt.Sprintf("BpfCtTimeoutRegularTcpFin: %d", ct.BpfCtTimeoutRegularTcpFin))
	}
	if ct.BpfCtTimeoutRegularTcpSyn != 0 {
		buffer = append(buffer, fmt.Sprintf("BpfCtTimeoutRegularTcpSyn: %d", ct.BpfCtTimeoutRegularTcpSyn))
	}

	return strings.Join(buffer, ", ")
}

// EgressTimeoutsMap is used to communicate EGW conntrack timeouts to the datapath.
type EgressTimeoutsMap interface {
	Lookup(sourceIP netip.Addr, destCIDR netip.Prefix) (*EgressTimeoutsVal4, error)
	Update(sourceIP netip.Addr, destCIDR netip.Prefix, connectionTimeouts ConnectionTimeouts) error
	Delete(sourceIP netip.Addr, destCIDR netip.Prefix) error
	IterateWithCallback(EgressTimeoutsIterateCallback) error
}

// EgressTimeoutsVal4 is the value of an egress timeouts map.
type EgressTimeoutsVal4 struct {
	/*ConnectionTimeouts are strictly for IPv4 egress connections*/
	ConnectionTimeouts ConnectionTimeouts `align:"egress_connection_timeouts"`
}

// egressTimeoutsMap is the internal representation of an egress timeouts map.
type egressTimeoutsMap struct {
	m *bpf.Map
}

func createEgressTimeoutsMapFromDaemonConfig(in struct {
	cell.In

	Lifecycle cell.Lifecycle
	*option.DaemonConfig
	PolicyConfig
}) (out struct {
	cell.Out

	bpf.MapOut[EgressTimeoutsMap]
	defines.NodeOut
}) {
	out.NodeDefines = map[string]string{
		"EGRESS_POLICY_TIMEOUTS_MAP": EgressTimeoutsMapName,
		"EGRESS_TIMEOUTS_MAP_SIZE":   fmt.Sprint(in.EgressGatewayPolicyMapMax),
	}

	if !in.EnableIPv4EgressGateway {
		return
	}

	out.MapOut = bpf.NewMapOut(EgressTimeoutsMap(createEgressTimeoutsMap(in.Lifecycle, in.PolicyConfig, ebpf.PinByName)))
	return
}

// CreatePrivatePolicyMap creates an unpinned policy map.
//
// Useful for testing.
func CreatePrivateEgressTimeoutsMap(lc cell.Lifecycle, cfg PolicyConfig) EgressTimeoutsMap {
	return createEgressTimeoutsMap(lc, cfg, ebpf.PinNone)
}

func createEgressTimeoutsMap(lc cell.Lifecycle, cfg PolicyConfig, pinning ebpf.PinType) *egressTimeoutsMap {
	m := bpf.NewMap(
		EgressTimeoutsMapName,
		ebpf.LPMTrie,
		&EgressPolicyKey4{},
		&EgressTimeoutsVal4{},
		cfg.EgressGatewayPolicyMapMax,
		0,
	).WithPressureMetric()

	lc.Append(cell.Hook{
		OnStart: func(cell.HookContext) error {
			switch pinning {
			case ebpf.PinNone:
				return m.CreateUnpinned()
			case ebpf.PinByName:
				return m.OpenOrCreate()
			}
			return fmt.Errorf("received unexpected pin type: %d", pinning)
		},
		OnStop: func(cell.HookContext) error {
			return m.Close()
		},
	})

	return &egressTimeoutsMap{m}
}

func OpenPinnedEgressTimeoutsMap() (EgressTimeoutsMap, error) {
	m, err := bpf.OpenMap(bpf.MapPath(EgressTimeoutsMapName), &EgressPolicyKey4{}, &EgressTimeoutsVal4{})
	if err != nil {
		return nil, err
	}

	return &egressTimeoutsMap{m}, nil
}

// New returns an egress timeouts value
func (v *EgressTimeoutsVal4) New() bpf.MapValue { return &EgressTimeoutsVal4{} }

// NewEgressTimeoutsVal4 returns a new EgressTimeoutsVal4 object representing for
// the given egress timeouts struct
func NewEgressTimeoutsVal4(connectionTimeouts ConnectionTimeouts) EgressTimeoutsVal4 {
	val := EgressTimeoutsVal4{}
	val.ConnectionTimeouts = connectionTimeouts

	return val
}

// Match returns true if the egressIP and gatewayIP parameters match the egress
// timeout value.
func (v *EgressTimeoutsVal4) Match(connectionTimeouts ConnectionTimeouts) bool {
	return v.ConnectionTimeouts == connectionTimeouts
}

// GetTimeouts returns the egress timeout value's egress timeouts.
func (v *EgressTimeoutsVal4) GetTimeouts() ConnectionTimeouts {
	return v.ConnectionTimeouts
}

// String returns the string representation of an egress timeout value.
func (v *EgressTimeoutsVal4) String() string {
	return fmt.Sprintf("%s", v.ConnectionTimeouts.String())
}

// Lookup returns the egress timeout object associated with the provided (source
// IP, destination CIDR) tuple.
func (m *egressTimeoutsMap) Lookup(sourceIP netip.Addr, destCIDR netip.Prefix) (*EgressTimeoutsVal4, error) {
	key := NewEgressPolicyKey4(sourceIP, destCIDR)
	val, err := m.m.Lookup(&key)
	if err != nil {
		return nil, err
	}

	return val.(*EgressTimeoutsVal4), err
}

// Update updates the (sourceIP, destCIDR) egress timeout entry with the provided
// egress and gateway IPs.
func (m *egressTimeoutsMap) Update(sourceIP netip.Addr, destCIDR netip.Prefix, connectionTimeouts ConnectionTimeouts) error {
	key := NewEgressPolicyKey4(sourceIP, destCIDR)
	val := NewEgressTimeoutsVal4(connectionTimeouts)

	return m.m.Update(&key, &val)
}

// Delete deletes the (sourceIP, destCIDR) egress timeouts entry.
func (m *egressTimeoutsMap) Delete(sourceIP netip.Addr, destCIDR netip.Prefix) error {
	key := NewEgressPolicyKey4(sourceIP, destCIDR)

	return m.m.Delete(&key)
}

// EgressTimeoutIterateCallback represents the signature of the callback function
// expected by the IterateWithCallback method, which in turn is used to iterate
// all the keys/values of an egress timeout map.
type EgressTimeoutsIterateCallback func(*EgressPolicyKey4, *EgressTimeoutsVal4)

// IterateWithCallback iterates through all the keys/values of an egress timeouts
// map, passing each key/value pair to the cb callback.
func (m egressTimeoutsMap) IterateWithCallback(cb EgressTimeoutsIterateCallback) error {
	return m.m.DumpWithCallback(func(k bpf.MapKey, v bpf.MapValue) {
		key := k.(*EgressPolicyKey4)
		value := v.(*EgressTimeoutsVal4)

		cb(key, value)
	})
}
