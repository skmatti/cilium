package loader

import (
	"context"
	"fmt"
	"net"
	"path"
	"strconv"
	"strings"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/command/exec"
	"github.com/cilium/cilium/pkg/datapath"
	"github.com/cilium/cilium/pkg/datapath/connector"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/node"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
)

func setupMultiNICDataPath(ctx context.Context, ep datapath.Endpoint, objPath string) error {
	// Graft from-container section for the egress direction.
	if err := graftL2Datapath(ctx, ep.MapPath(), objPath, "from-container", int(connector.EgressMapIndex)); err != nil {
		scopedLog := ep.Logger(Subsystem).WithFields(logrus.Fields{
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
	// Graft to-container section for the ingress direction.
	if err := graftL2Datapath(ctx, ep.MapPath(), objPath, "to-container", int(connector.IngressMapIndex)); err != nil {
		scopedLog := ep.Logger(Subsystem).WithFields(logrus.Fields{
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
func ReloadParentDevDatapath(ctx context.Context, device, objDir string, ep datapath.Endpoint) error {
	hostObjPath := path.Join(ep.StateDir(), hostEndpointObj)
	parentDevObjPath := path.Join(objDir, hostEndpointNetdevPrefix+device+".o")
	scopedLog := ep.Logger(Subsystem).WithFields(logrus.Fields{
		logfields.Path:      parentDevObjPath,
		logfields.Interface: device,
	})
	scopedLog.Info("Loading bpf progs for the parent device")

	symbols := []string{symbolFromHostNetdevEp, symbolToHostNetdevEp}
	directions := []string{dirIngress, dirEgress}

	v4Address, err := node.FirstV4GlobalAddr(device)
	if err != nil {
		return err
	}
	scopedLog.WithField(logfields.IPv4, v4Address).Info("Enable IPv4 Masquerade")
	bpfMasqIPv4Addrs := map[string]net.IP{
		device: v4Address,
	}

	if err := patchHostNetdevDatapath(ep, hostObjPath, parentDevObjPath, device, bpfMasqIPv4Addrs); err != nil {
		return err
	}

	for i, symbol := range symbols {
		progs := []progDefinition{{progName: symbol, direction: directions[i]}}
		finalize, err := replaceDatapath(ctx, device, parentDevObjPath, progs, "")
		if err != nil {
			// Don't log an error here if the context was canceled or timed out;
			// this log message should only represent failures with respect to
			// loading the program.
			if ctx.Err() == nil {
				scopedLog.WithError(err).Warningf("JoinEP: Failed to load program for host endpoint (%s)", symbol)
			}
			return err
		}
		defer finalize()
	}
	return nil
}

// graftL2Datapath replaces obj in tail call map for L2 interfaces.
// Since L2 interfaces are already moved to the pod namespace, we use graft
// to load tail call to the predefined map. Therefore, we need to avoid
// unconditionally migrating cilium_calls introduced in upstream: https://github.com/cilium/cilium/pull/28740
func graftL2Datapath(ctx context.Context, mapPath, objPath, progSec string, key int) error {
	scopedLog := log.WithField("mapPath", mapPath).WithField("objPath", objPath).
		WithField("progSection", progSec).WithField("direction", key)

	scopedLog.Debug("Loading CollectionSpec from ELF")
	spec, err := bpf.LoadCollectionSpec(objPath)
	if err != nil {
		return fmt.Errorf("loading eBPF ELF: %w", err)
	}

	// Remove "cilium_calls_" from CollectionSpec to prevent map migration.
	// For macvtap interfaces, the map is prdefined and remains stabel
	// in pkg/datapath/connector/utils.go.
	// "cilium_policy_" map can still be migrated and repinned
	// if the map properties have changed.
	for name := range spec.Maps {
		if strings.HasPrefix(name, "cilium_calls_") {
			delete(spec.Maps, name)
			scopedLog.Debug("Removing cilium_calls_ from CollectionSpec during graft process")
		}
	}

	scopedLog.Debug("Starting bpffs map migration")
	if err := bpf.StartBPFFSMigration(bpf.MapPrefixPath(), spec); err != nil {
		return fmt.Errorf("Failed to start bpffs map migration: %w", err)
	}

	var revert bool
	defer func() {
		scopedLog.Debug("Finalizing bpffs map migration")
		if err := bpf.FinalizeBPFFSMigration(bpf.MapPrefixPath(), spec, revert); err != nil {
			scopedLog.WithError(err).WithFields(logrus.Fields{logfields.BPFMapPath: mapPath, "objPath": objPath}).
				Error("Could not finalize bpffs map migration")
		}
	}()

	// FIXME: replace exec with native call
	// Load the object from the tail call map with the provided key.
	args := []string{"exec", "bpf", "graft", mapPath, "key", strconv.Itoa(key),
		"obj", objPath, "sec", progSec,
	}
	scopedLog.Info("Grafting program")
	cmd := exec.CommandContext(ctx, "tc", args...).WithFilters(libbpfFixupMsg)
	if _, err := cmd.CombinedOutput(log, true); err != nil {
		revert = true
		return fmt.Errorf("Failed to graft tc object: %s", err)
	}

	return nil
}

// UnloadParentDevDatapath unloads ebpf programs by removing all tc filters
// on the parent device. Both ingress and egress are attempted to unload.
func UnloadParentDevDatapath(ctx context.Context, device string) error {
	directions := []uint32{netlink.HANDLE_MIN_EGRESS, netlink.HANDLE_MIN_INGRESS}
	for _, dir := range directions {
		if err := RemoveTCFilters(device, dir); err != nil {
			return fmt.Errorf("failed to remove bpf program on device %q: %v", device, err)
		}
	}
	return nil
}
