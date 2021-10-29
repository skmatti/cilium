package loader

import (
	"context"
	"fmt"
	"net"
	"path"

	"github.com/cilium/cilium/pkg/datapath"
	"github.com/cilium/cilium/pkg/datapath/connector"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/node"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
)

func setupMultiNICDataPath(ctx context.Context, ep datapath.Endpoint, objPath string) error {
	// Graft from-container section for the egress direction.
	if err := graftDatapath(ctx, ep.MapPath(), objPath, "from-container", int(connector.EgressMapIndex)); err != nil {
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
	if err := graftDatapath(ctx, ep.MapPath(), objPath, "to-container", int(connector.IngressMapIndex)); err != nil {
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
		finalize, err := replaceDatapath(ctx, device, parentDevObjPath, symbol, directions[i], "")
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
