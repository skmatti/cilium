package features

import (
	"fmt"

	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/option"
	"github.com/spf13/pflag"
)

var (
	// Used when config can't be injected by the Hive
	GlobalConfig = defaultConfig
)

var Cell = cell.Module(
	"features",
	"Features",

	cell.Config(defaultConfig),
	cell.Invoke(func(config Config) {
		if config.DisableNetworkPolicyCRD {
			config.EnableCiliumNetworkPolicy = false
			config.EnableCiliumClusterWideNetworkPolicy = false
		}
		GlobalConfig = config
	}),
)

// Config struct used to gate OSS features that otherwise have no means to be disabled
type Config struct {
	EnableLoadBalancerIPAM bool `mapstructure:"enable-lbipam"`
	// TODO(@avelagap): Remove EnableCiliumNodeConfig flag after b/296257668
	EnableCiliumNodeConfig bool `mapstructure:"enable-cnc"`
	// DisableIPv6Tunnel determines if IPv6 tunnel should be explicitly disabled. Currently Tunnel is enabled for both IP families by default.
	DisableIPv6Tunnel bool
	// (Deprecated) DisableCiliumNetworkPolicyCRD instructs Cilium to ignore CNP and CCNP.
	// It will be replaced by EnableCiliumNetworkPolicy and EnableCiliumCluterWideNetworkPolicy.
	// For backward compatibility, when it is set to true, the other two flags will be set to False.
	DisableNetworkPolicyCRD bool
	// EnableCiliumCluterWideNetworkPolicy instructs Cilium to allow CNP installation
	EnableCiliumNetworkPolicy bool
	// EnableCiliumCluterWideNetworkPolicy instructs Cilium to allow CCNP installation
	EnableCiliumClusterWideNetworkPolicy bool
}

var defaultConfig = Config{
	EnableLoadBalancerIPAM:               false,
	EnableCiliumNodeConfig:               false,
	DisableIPv6Tunnel:                    false,
	DisableNetworkPolicyCRD:              false,
	EnableCiliumNetworkPolicy:            true,
	EnableCiliumClusterWideNetworkPolicy: true,
}

func (cfg Config) Flags(flags *pflag.FlagSet) {
	flags.Bool(option.EnableLoadBalancerIPAM, defaultConfig.EnableLoadBalancerIPAM, "Enable LoadBalancer IP Address Management (IPAM)")
	flags.MarkHidden(option.EnableLoadBalancerIPAM)

	flags.Bool(option.EnableCiliumNodeConfig, defaultConfig.EnableCiliumNodeConfig, "Enable CiliumNodeConfig")
	flags.MarkHidden(option.EnableCiliumNodeConfig)

	flags.Bool(option.DisableIPv6Tunnel, defaultConfig.DisableIPv6Tunnel, "Disable tunnel for IPv6")
	flags.MarkHidden(option.DisableIPv6Tunnel)

	flags.Bool(option.DisableNetworkPolicyCRDName, defaultConfig.DisableNetworkPolicyCRD, "Disable use of CiliumNetworkPolicy and CiliumClusterwideNetworkPolicy CRD")
	flags.MarkDeprecated(option.DisableNetworkPolicyCRDName,
		fmt.Sprintf("This option will be removed. Please use --%s and --%s instead.", option.EnableCiliumNetworkPolicyName, option.EnableCiliumClusterWideNetworkPolicyName))

	flags.Bool(option.EnableCiliumNetworkPolicyName, defaultConfig.EnableCiliumNetworkPolicy, "Enable use of CiliumNetworkPolicy CRD")
	flags.MarkHidden(option.EnableCiliumNetworkPolicyName)

	flags.Bool(option.EnableCiliumClusterWideNetworkPolicyName, defaultConfig.EnableCiliumClusterWideNetworkPolicy, "Enable use of CiliumClusterwideNetworkPolicy CRD")
	flags.MarkHidden(option.EnableCiliumClusterWideNetworkPolicyName)
}
