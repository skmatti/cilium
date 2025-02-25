package multinicconfig

import (
	"github.com/cilium/hive/cell"
	"github.com/spf13/pflag"
)

const (
	EnableFlag            = "enable-google-multi-nic"
	EnableL3MigrationFlag = "enable-google-multi-nic-l3-migration"
)

var Cell = cell.Config(defaultConfig)

var (
	// Used when config can't be injected by the Hive
	GlobalConfig = defaultConfig
)

type Config struct {
	// EnableGoogleMultiNIC enables Google multi NIC support
	EnableGoogleMultiNIC bool
	// EnableGoogleMultiNICL3Migration enables Google multi NIC migration. When enabled, L3 multi-network configuration is migrated to cilium-cni.
	EnableGoogleMultiNICL3Migration bool
}

var defaultConfig = Config{
	EnableGoogleMultiNIC:            false,
	EnableGoogleMultiNICL3Migration: false,
}

func (cfg Config) Flags(flags *pflag.FlagSet) {
	flags.Bool(EnableFlag, defaultConfig.EnableGoogleMultiNIC, "Enable Google multi NIC support")
	flags.MarkHidden(EnableFlag)

	flags.Bool(EnableL3MigrationFlag, defaultConfig.EnableGoogleMultiNICL3Migration, "Enable Google multi NIC L3 migration.")
	flags.MarkHidden(EnableL3MigrationFlag)
}

func Enabled() bool {
	return GlobalConfig.EnableGoogleMultiNIC
}

func L3MigrationEnabled() bool {
	return GlobalConfig.EnableGoogleMultiNICL3Migration
}
