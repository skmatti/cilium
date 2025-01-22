package multinicconfig

import (
	"github.com/cilium/hive/cell"
	"github.com/spf13/pflag"
)

const (
	EnableFlag = "enable-google-multi-nic"
)

var Cell = cell.Config(defaultConfig)

var (
	// Used when config can't be injected by the Hive
	GlobalConfig = defaultConfig
)

type Config struct {
	EnableGoogleMultiNIC bool
}

var defaultConfig = Config{
	EnableGoogleMultiNIC: false,
}

func (cfg Config) Flags(flags *pflag.FlagSet) {
	flags.Bool(EnableFlag, defaultConfig.EnableGoogleMultiNIC, "Enable Google multi NIC support")
	flags.MarkHidden(EnableFlag)
}

func Enabled() bool {
	return GlobalConfig.EnableGoogleMultiNIC
}
