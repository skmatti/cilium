package windows

import (
	"github.com/cilium/cilium/operator/option"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/spf13/pflag"
)

var Cell = cell.Module(
	"windows",
	"Windows",

	cell.Config(defaultConfig),
	cell.Invoke(startSynchronizingWindowsNodes),
)

type Config struct {
	SynchronizeK8sWindowsNodes bool
}

var defaultConfig = Config{
	SynchronizeK8sWindowsNodes: false,
}

func (cfg Config) Flags(flags *pflag.FlagSet) {
	flags.Bool(option.SynchronizeK8sWindowsNodes, false, "")
	flags.MarkHidden(option.SynchronizeK8sWindowsNodes)
}
