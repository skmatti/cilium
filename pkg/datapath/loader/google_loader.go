package loader

import (
	"context"
	"errors"
	"fmt"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/datapath/connector"
	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
	datapath "github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maps/policymap"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/ebpf"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
)

func setupMultiNICDataPath(ctx context.Context, ep datapath.Endpoint, objPath string) error {
	// Map of programs to be loaded at tail-call map with the index
	p := map[uint32]string{
		uint32(connector.EgressMapIndex):  "cil_from_container",
		uint32(connector.IngressMapIndex): "cil_to_container",
	}

	if err := reloadL2Datapath(ep.MapPath(), objPath, p); err != nil {
		scopedLog := ep.Logger(subsystem).WithFields(logrus.Fields{
			logfields.Path: objPath,
		})
		// Don't log an error here if the context was canceled or timed out;
		// this log message should only represent failures with respect to
		// loading the program.
		if ctx.Err() == nil {
			scopedLog.WithError(err).Warn("JoinEP: Failed to load program")
		}
		return err
	}
	return nil
}

// ReloadParentDevDatapath loads bpf_host programs on the provided parent device.
// The program object file (bpf_host.o) is compiled for the host device and pointed
// by the object path of the host endpoint.
// The bpf masquerade is always turned on for the parent device.
// The masquerade address is the first global IPv4 address found on the node.
func (l *loader) ReloadParentDevDatapath(ctx context.Context, device string, ep datapath.Endpoint) error {
	scopedLog := ep.Logger(subsystem).WithFields(logrus.Fields{
		logfields.Interface: device,
	})
	scopedLog.Info("Loading bpf progs for the parent device")

	iface, err := safenetlink.LinkByName(device)
	if err != nil {
		return err
	}

	netdevConsts, netdevRenames, err := l.patchHostNetdevDatapath(ep, device)
	if err != nil {
		return err
	}

	dirs := directoryInfo{
		Library: option.Config.BpfDir,
		Runtime: option.Config.StateDir,
		State:   ep.StateDir(),
		Output:  ep.StateDir(),
	}
	cfg := l.getNodeConfig()
	spec, _, err := l.templateCache.fetchOrCompile(ctx, cfg, ep, &dirs, nil)
	if err != nil {
		return fmt.Errorf("loading eBPF ELF: %w", err)
	}
	scopedLog.Infof("spec :%+v", spec)

	// Replace all occurrences of the template endpoint ID with the real ID.
	for _, name := range []string{
		policymap.PolicyCallMapName,
		policymap.PolicyEgressCallMapName,
	} {
		pm, ok := spec.Maps[name]
		if !ok {
			continue
		}

		for i, kv := range pm.Contents {
			if kv.Key == (uint32)(templateLxcID) {
				pm.Contents[i].Key = (uint32)(ep.GetID())
			}
		}
	}

	coll, commit, err := loadDatapath(spec, netdevRenames, netdevConsts)
	if err != nil {
		return err
	}
	defer coll.Close()

	linkDir := bpffsDeviceLinksDir(bpf.CiliumPath(), iface)

	// Attach cil_from_netdev to ingress.
	if err := attachSKBProgram(iface, coll.Programs[symbolFromHostNetdevEp], symbolFromHostNetdevEp,
		linkDir, netlink.HANDLE_MIN_INGRESS, option.Config.EnableTCX); err != nil {
		return fmt.Errorf("interface %s ingress: %w", device, err)
	}

	// Attach cil_to_netdev to egress.
	if err := attachSKBProgram(iface, coll.Programs[symbolToHostNetdevEp], symbolToHostNetdevEp,
		linkDir, netlink.HANDLE_MIN_EGRESS, option.Config.EnableTCX); err != nil {
		return fmt.Errorf("interface %s egress: %w", device, err)
	}

	if err := commit(); err != nil {
		return fmt.Errorf("committing bpf pins: %w", err)
	}

	return nil
}

// reloadL2Datapath replaces obj in tail call map for L2 interfaces.
// Since L2 interfaces are already moved to the pod namespace we need to avoid
// unconditionally migrating cilium_calls introduced in upstream: https://github.com/cilium/cilium/pull/28740
func reloadL2Datapath(mapPath, objPath string, progs map[uint32]string) error {
	scopedLog := log.WithField("mapPath", mapPath).WithField("objPath", objPath)
	scopedLog.Debug("Loading CollectionSpec from ELF")
	spec, err := bpf.LoadCollectionSpec(objPath)
	if err != nil {
		return fmt.Errorf("loading eBPF ELF: %w", err)
	}

	scopedLog.Debug("Starting bpffs map migration")
	if err := bpf.StartBPFFSMigration(bpf.TCGlobalsPath(), spec); err != nil {
		return fmt.Errorf("failed to start bpffs map migration: %w", err)
	}

	var revert bool
	defer func() {
		scopedLog.Debug("Finalizing bpffs map migration")
		if err := bpf.FinalizeBPFFSMigration(bpf.TCGlobalsPath(), spec, revert); err != nil {
			scopedLog.WithError(err).WithFields(logrus.Fields{logfields.BPFMapPath: mapPath, "objPath": objPath}).
				Error("Could not finalize bpffs map migration")
		}
	}()

	pinPath := bpf.TCGlobalsPath()
	opts := bpf.CollectionOptions{
		CollectionOptions: ebpf.CollectionOptions{
			Maps: ebpf.MapOptions{PinPath: pinPath},
		},
	}

	coll, _, err := bpf.LoadCollection(spec, &opts)
	var ve *ebpf.VerifierError
	if errors.As(err, &ve) {
		return fmt.Errorf("error from bpf verifier: %w verifier log:%+v", err, ve)
	}
	defer coll.Close()
	progArr, err := ebpf.LoadPinnedMap(mapPath, nil)
	if err != nil {
		return fmt.Errorf("failed to find map object: %s, %v", mapPath, err)
	}
	for index, progName := range progs {
		prog, ok := coll.Programs[progName]
		if !ok {
			return fmt.Errorf("could not find name of program %s in collection", progName)
		}
		if err = progArr.Update(index, prog, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("error updating tail map %s", progName)
		}
	}
	return nil
}

// UnloadParentDevDatapath unloads ebpf programs by removing all tc filters
// on the parent device. Both ingress and egress are attempted to unload.
func UnloadParentDevDatapath(ctx context.Context, device string) error {
	link, err := safenetlink.LinkByName(device)
	if err != nil {
		return fmt.Errorf("failed to find device %q: %w", device, err)
	}

	if err := removeTCFilters(link, netlink.HANDLE_MIN_INGRESS); err != nil {
		return fmt.Errorf("failed to remove ingress filter on device %q: %w", device, err)
	}
	if err := removeTCFilters(link, netlink.HANDLE_MIN_EGRESS); err != nil {
		return fmt.Errorf("failed to remove egress filter on device %q: %w", device, err)
	}

	return nil
}
