package multinicconfig

import (
	"github.com/cilium/hive/cell"
	"github.com/spf13/pflag"
)

const (
	EnableFlag                                   = "enable-google-multi-nic"
	EnableL3MigrationFlag                        = "enable-google-multi-nic-l3-migration"
	PopulateGCENICInfo                           = "populate-gce-nic-info"
	EnableGoogleTunnelThroughSecondaryInterfaces = "enable-google-tunnel-through-secondary-interfaces"
	EnableHostDeviceRoutingReconciliation        = "enable-host-device-routing-reconciliation"
	NetworkReconcilerRetryLimit                  = "network-reconciler-retry-limit"
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
	PopulateGCENICInfo              bool
	// EnableGoogleTunnelThroughSecondaryInterfaces is used to enable
	// tunneling traffic through secondary host interfaces on the L3 networks.
	//
	// Ref. go/island-mode-secondary-networks
	EnableGoogleTunnelThroughSecondaryInterfaces bool `mapstructure:"enable-google-tunnel-through-secondary-interfaces"`
	// EnableHostDeviceRoutingReconciliation enables reconciliation of host device routing records.
	EnableHostDeviceRoutingReconciliation bool
	// NetworkReconcilerRetryLimit is the maximum number of retries for network reconciliation. 0 means infinite retries.
	NetworkReconcilerRetryLimit int
}

var defaultConfig = Config{
	EnableGoogleMultiNIC:                         false,
	EnableGoogleMultiNICL3Migration:              false,
	PopulateGCENICInfo:                           false,
	EnableGoogleTunnelThroughSecondaryInterfaces: false,
	EnableHostDeviceRoutingReconciliation:        true,
	NetworkReconcilerRetryLimit:                  0,
}

func (cfg Config) Flags(flags *pflag.FlagSet) {
	flags.Bool(EnableFlag, defaultConfig.EnableGoogleMultiNIC, "Enable Google multi NIC support")
	flags.MarkHidden(EnableFlag)

	flags.Bool(EnableL3MigrationFlag, defaultConfig.EnableGoogleMultiNICL3Migration, "Enable Google multi NIC L3 migration.")
	flags.MarkHidden(EnableL3MigrationFlag)

	flags.Bool(PopulateGCENICInfo, defaultConfig.PopulateGCENICInfo, "Populate GCE NIC information as node annotation.")
	flags.MarkHidden(PopulateGCENICInfo)

	flags.Bool(EnableGoogleTunnelThroughSecondaryInterfaces, defaultConfig.EnableGoogleTunnelThroughSecondaryInterfaces, "Enable tunneling through secondary host interfaces on L3 networks.")
	flags.MarkHidden(EnableGoogleTunnelThroughSecondaryInterfaces)

	flags.Bool(EnableHostDeviceRoutingReconciliation, defaultConfig.EnableHostDeviceRoutingReconciliation, "Enable host device routing reconciliation on L2/L3 networks.")
	flags.MarkHidden(EnableHostDeviceRoutingReconciliation)

	flags.Int(NetworkReconcilerRetryLimit, defaultConfig.NetworkReconcilerRetryLimit, "Maximum number of retries for network reconciliation. 0 means infinite retries.")
	flags.MarkHidden(NetworkReconcilerRetryLimit)
}

func Enabled() bool {
	return GlobalConfig.EnableGoogleMultiNIC
}

func L3MigrationEnabled() bool {
	return GlobalConfig.EnableGoogleMultiNICL3Migration
}
