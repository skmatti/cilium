package linux

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/gke/features"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/testutils"
	"github.com/cilium/cilium/pkg/testutils/netns"
	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/cilium/statedb"
)

func TestDevicesController_ExcludeDevicesWithUserProvidedPrefixes(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	testutils.PrivilegedTest(t)
	devicesControllerTestSetup(t)

	tlog := hivetest.Logger(t)
	ns := netns.NewNetNS(t)
	ns.Do(func() error {
		var (
			db           *statedb.DB
			devicesTable statedb.Table[*tables.Device]
		)
		h := hive.New(
			DevicesControllerCell,
			cell.Provide(func() (*netlinkFuncs, error) { return makeNetlinkFuncs() }),
			cell.Invoke(func(db_ *statedb.DB, devicesTable_ statedb.Table[*tables.Device]) {
				db = db_
				devicesTable = devicesTable_
			}))

		features.GlobalConfig.DevicePrefixesToExclude = []string{"excluded"}

		err := h.Start(tlog, ctx)
		require.NoError(t, err)
		require.NoError(t, createDummy("dummy0", "192.168.0.1/24", false))
		require.NoError(t, createDummy("excluded", "192.168.1.1/24", false))

		for {
			rxn := db.ReadTxn()
			devs, invalidated := tables.SelectedDevices(devicesTable, rxn)
			if len(devs) == 1 && devs[0].Name == "dummy0" {
				break
			}

			// Not yet what we expected, wait for changes and try again.
			select {
			case <-ctx.Done():
				t.Fatalf("Test timed out while waiting for devices, last seen: %v", tables.DeviceNames(devs))
			case <-invalidated:
			}
		}

		err = h.Stop(tlog, context.TODO())
		require.NoError(t, err)
		return nil
	})
}
