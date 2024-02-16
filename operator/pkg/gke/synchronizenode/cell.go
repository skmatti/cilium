package synchronizenode

import (
	"github.com/cilium/cilium/operator/option"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/spf13/pflag"
)

var Cell = cell.Module(
	"synchronizenode",
	"SynchronizeNode",

	cell.Config(defaultConfig),
	cell.Invoke(startSynchronizingNodes),
)

type Config struct {
	SynchronizeK8sWindowsNodes bool
	SynchronizeMigratingNodes  bool
}

var defaultConfig = Config{
	SynchronizeK8sWindowsNodes: false,
	SynchronizeMigratingNodes:  false,
}

func (cfg Config) Flags(flags *pflag.FlagSet) {
	flags.Bool(option.SynchronizeK8sWindowsNodes, false, "")
	flags.MarkHidden(option.SynchronizeK8sWindowsNodes)

	flags.Bool(option.SynchronizeMigratingNodes, false, "")
	flags.MarkHidden(option.SynchronizeMigratingNodes)
}
