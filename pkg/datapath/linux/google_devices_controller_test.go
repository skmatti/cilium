package linux

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/gke/features"
	"github.com/cilium/cilium/pkg/gke/multinic/multinicconfig"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/testutils"
	"github.com/cilium/cilium/pkg/testutils/netns"
	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/cilium/statedb"
)

func TestDevicesController_GoogleExclusion(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	testutils.PrivilegedTest(t)
	devicesControllerTestSetup(t)

	tlog := hivetest.Logger(t)
	ns := netns.NewNetNS(t)
	const excludedPCI = "aa:bb:cc:dd"
	ns.Do(func() error {
		var (
			db           *statedb.DB
			devicesTable statedb.Table[*tables.Device]
		)
		h := hive.New(
			DevicesControllerCell,
			cell.Provide(func() (*netlinkFuncs, error) { return makeNetlinkFuncs() }),
			cell.Provide(func() *googleDeviceFuncs {
				return &googleDeviceFuncs{
					ToPCIAddr: func(iface string) (string, error) {
						if iface == "excluded-pci" {
							return excludedPCI, nil
						}
						return "", nil
					},
				}
			}),
			cell.Invoke(func(db_ *statedb.DB, devicesTable_ statedb.Table[*tables.Device], dc *devicesController) {
				db = db_
				devicesTable = devicesTable_
				dc.excludedPCIs = map[string]any{excludedPCI: nil}
			}))

		features.GlobalConfig.DevicePrefixesToExclude = []string{"excluded-pre"}

		err := h.Start(tlog, ctx)
		require.NoError(t, err)
		require.NoError(t, createDummy("dummy0", "192.168.0.1/24", false))
		require.NoError(t, createDummy("excluded-pre-01", "192.168.1.1/24", false))
		require.NoError(t, createDummy("excluded-pci", "192.168.2.1/24", false))

		require.NoError(t, checkDeviceTable(ctx, db, devicesTable, []string{"dummy0"}))

		err = h.Stop(tlog, context.TODO())
		require.NoError(t, err)
		return nil
	})
}

func TestDevicesController_GoogleDeviceManager(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	testutils.PrivilegedTest(t)
	devicesControllerTestSetup(t)

	tlog := hivetest.Logger(t)
	ns := netns.NewNetNS(t)
	const excludedPCI = "aa:bb:cc:dd"
	ns.Do(func() error {
		var (
			db           *statedb.DB
			devicesTable statedb.Table[*tables.Device]
			gdm          *GoogleDeviceManager
		)
		h := hive.New(
			DevicesControllerCell,
			cell.Provide(func() (*netlinkFuncs, error) { return makeNetlinkFuncs() }),
			cell.Provide(func() multinicconfig.Config {
				return multinicconfig.Config{
					EnableGoogleMultiNIC: true,
				}
			}),
			cell.Provide(func() *googleDeviceFuncs {
				return &googleDeviceFuncs{
					ToPCIAddr: func(iface string) (string, error) {
						if iface == "excluded-pci" {
							return excludedPCI, nil
						}
						return "", nil
					},
				}
			}),
			cell.Invoke(func(db_ *statedb.DB, devicesTable_ statedb.Table[*tables.Device], gdm_ *GoogleDeviceManager) {
				db = db_
				devicesTable = devicesTable_
				gdm = gdm_
			}))

		features.GlobalConfig.DevicePrefixesToExclude = []string{"excluded-pre"}

		err := h.Start(tlog, ctx)
		require.NoError(t, err)
		require.NoError(t, createDummy("dummy0", "192.168.0.1/24", false))
		require.NoError(t, createDummy("excluded-pci", "192.168.2.1/24", false))

		require.NoError(t, checkDeviceTable(ctx, db, devicesTable, []string{"dummy0", "excluded-pci"}))
		gdm.ExcludeDevices(map[string]any{excludedPCI: nil})
		require.NoError(t, checkDeviceTable(ctx, db, devicesTable, []string{"dummy0"}))

		err = h.Stop(tlog, context.TODO())
		require.NoError(t, err)
		return nil
	})
}

func checkDeviceTable(ctx context.Context, db *statedb.DB, devicesTable statedb.Table[*tables.Device], want []string) error {
	for {
		rxn := db.ReadTxn()
		devs, invalidated := tables.SelectedDevices(devicesTable, rxn)
		got := tables.DeviceNames(devs)
		if cmp.Equal(got, want) {
			break
		}

		// Not yet what we expected, wait for changes and try again.
		select {
		case <-ctx.Done():
			return fmt.Errorf("test timed out while waiting for devices, last seen: %v", got)
		case <-invalidated:
		}
	}
	return nil
}
