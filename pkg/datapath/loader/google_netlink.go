package loader

import (
	"context"
	"fmt"
	"strconv"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/command/exec"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/sirupsen/logrus"
)

// graftDatapath replaces obj in tail call map
func graftDatapath(ctx context.Context, mapPath, objPath, progSec string, key int) error {
	scopedLog := log.WithField("mapPath", mapPath).WithField("objPath", objPath).
		WithField("progSection", progSec).WithField("direction", key)

	scopedLog.Debug("Loading CollectionSpec from ELF")
	spec, err := bpf.LoadCollectionSpec(objPath)
	if err != nil {
		return fmt.Errorf("loading eBPF ELF: %w", err)
	}
	scopedLog.Debug("Starting bpffs map migration")
	if err := bpf.StartBPFFSMigration(bpf.TCGlobalsPath(), spec); err != nil {
		return fmt.Errorf("Failed to start bpffs map migration: %w", err)
	}

	var revert bool
	defer func() {
		scopedLog.Debug("Finalizing bpffs map migration")
		if err := bpf.FinalizeBPFFSMigration(bpf.TCGlobalsPath(), spec, revert); err != nil {
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
	cmd := exec.CommandContext(ctx, "tc", args...)
	if _, err := cmd.CombinedOutput(log, true); err != nil {
		revert = true
		return fmt.Errorf("Failed to graft tc object: %s", err)
	}

	return nil
}
