package egressmap

import (
	"errors"
	"net/netip"
	"testing"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/ebpf"
	"github.com/cilium/cilium/pkg/testutils"
	"github.com/cilium/ebpf/rlimit"
	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/assert"
)

func TestEgressTimeoutsMap(t *testing.T) {
	testutils.PrivilegedTest(t)

	bpf.CheckOrMountFS("")
	assert.Nil(t, rlimit.RemoveMemlock())

	egressTimeoutsMap := createEgressTimeoutsMap(hivetest.Lifecycle(t), DefaultPolicyConfig, ebpf.PinNone)

	sourceIP1 := netip.MustParseAddr("1.1.1.1")
	sourceIP2 := netip.MustParseAddr("1.1.1.2")

	destCIDR1 := netip.MustParsePrefix("2.2.1.0/24")
	destCIDR2 := netip.MustParsePrefix("2.2.2.0/24")

	connectionTimeouts := ConnectionTimeouts{
		BpfCtTimeoutRegularAny:    1000,
		BpfCtTimeoutRegularTcp:    2000,
		BpfCtTimeoutRegularTcpFin: 3000,
		BpfCtTimeoutRegularTcpSyn: 4000,
	}
	connectionTimeouts2 := ConnectionTimeouts{
		BpfCtTimeoutRegularAny: 5000,
		BpfCtTimeoutRegularTcp: 6000,
	}

	err := egressTimeoutsMap.Update(sourceIP1, destCIDR1, connectionTimeouts)
	assert.Nil(t, err)

	err = egressTimeoutsMap.Update(sourceIP2, destCIDR2, connectionTimeouts2)
	assert.Nil(t, err)

	val, err := egressTimeoutsMap.Lookup(sourceIP1, destCIDR1)
	assert.Nil(t, err)
	assert.Equal(t, val.GetTimeouts(), connectionTimeouts)

	val, err = egressTimeoutsMap.Lookup(sourceIP2, destCIDR2)
	assert.Nil(t, err)
	assert.Equal(t, val.GetTimeouts(), connectionTimeouts2)

	err = egressTimeoutsMap.Delete(sourceIP2, destCIDR2)
	assert.Nil(t, err)

	val, err = egressTimeoutsMap.Lookup(sourceIP1, destCIDR1)
	assert.Nil(t, err)
	assert.Equal(t, val.GetTimeouts(), connectionTimeouts)

	_, err = egressTimeoutsMap.Lookup(sourceIP2, destCIDR2)
	assert.True(t, errors.Is(err, ebpf.ErrKeyNotExist))

	err = egressTimeoutsMap.Update(sourceIP1, destCIDR1, connectionTimeouts2)
	assert.Nil(t, err)

	val, err = egressTimeoutsMap.Lookup(sourceIP1, destCIDR1)
	assert.Nil(t, err)
	assert.Equal(t, val.GetTimeouts(), connectionTimeouts2)
}
