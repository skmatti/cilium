package linux

import (
	"fmt"
	"log/slog"
	"maps"
	"reflect"

	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/gke/multinic/multinicconfig"
	"github.com/cilium/cilium/pkg/gke/multinic/nic"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/hive/cell"
)

// GoogleDeviceManager is a wrapper to allow access to the private deviceController.
type GoogleDeviceManager struct {
	log *slog.Logger
	dc  *devicesController
}

type googleDevicesManagerParams struct {
	cell.In
	Log    *slog.Logger
	Config multinicconfig.Config
}

func newGoogleDeviceManager(p googleDevicesManagerParams, dc *devicesController) *GoogleDeviceManager {
	if !p.Config.EnableGoogleMultiNIC {
		return nil
	}
	return &GoogleDeviceManager{log: p.Log, dc: dc}
}

const googleDeviceExclusionReason = "Google: Excluded interface corresponding to Device typed network"

// ExcludeDevices unselect devices with PCI addresses in the device table.
// Returns true if the passed in devices is different from dc.excludedPCIs.
// Caller needs to trigger EBPF reloading to actually remove EBPF from those devices.
func (gdm *GoogleDeviceManager) ExcludeDevices(pcis map[string]any) (bool, error) {
	dc := gdm.dc
	// Make sure it's initialized
	<-dc.initialized
	dc.mu.Lock()
	defer dc.mu.Unlock()
	if reflect.DeepEqual(dc.excludedPCIs, pcis) {
		// nothing to update
		return false, nil
	}
	// Make a copy so it won't be mutated by callers.
	dc.excludedPCIs = maps.Clone(pcis)
	txn := dc.params.DB.WriteTxn(dc.params.DeviceTable, dc.params.RouteTable)
	devs, _ := tables.SelectedDevices(dc.params.DeviceTable, txn)
	for _, d := range devs {
		pciAddr, err := dc.params.GoogleDeviceFuncs.ToPCIAddr(d.Name)
		if err != nil {
			gdm.log.Warn("Unable to get PCI address. Continuing to allow cilium management.", "NICName", d.Name, "error", err)
			continue
		}
		if _, ok := dc.excludedPCIs[pciAddr]; !ok {
			continue
		}

		// unselect the NIC
		newDev := d.DeepCopy()
		newDev.Selected = false
		newDev.NotSelectedReason = googleDeviceExclusionReason
		if _, _, err := dc.params.DeviceTable.Insert(txn, newDev); err != nil {
			return false, fmt.Errorf("failed to update table entry for device %s: %v", d.Name, err)
		}
		gdm.log.Info("Excluded NIC from device table", "Name", d.Name, "PCI", pciAddr)
	}
	dc.log.Info("Devices selected", logfields.Devices, dc.deviceNameSet(txn).UnsortedList())
	txn.Commit()
	return true, nil
}

type googleDeviceFuncs struct {
	ToPCIAddr func(iface string) (string, error)
}

func makeGoogleDeviceFuncs() *googleDeviceFuncs {
	return &googleDeviceFuncs{
		ToPCIAddr: nic.ToPCIAddr,
	}
}
