package features

import (
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
	cell.Invoke(func(config Config) { GlobalConfig = config }),
)

// Config struct used to gate OSS features that otherwise have no means to be disabled
type Config struct {
	EnableLoadBalancerIPAM bool `mapstructure:"enable-lbipam"`
	// TODO(@avelagap): Remove EnableCiliumNodeConfig flag after b/296257668
	EnableCiliumNodeConfig bool `mapstructure:"enable-cnc"`
}

var defaultConfig = Config{
	EnableLoadBalancerIPAM: false,
	EnableCiliumNodeConfig: false,
}

func (cfg Config) Flags(flags *pflag.FlagSet) {
	flags.Bool(option.EnableLoadBalancerIPAM, defaultConfig.EnableLoadBalancerIPAM, "Enable LoadBalancer IP Address Management (IPAM)")
	flags.MarkHidden(option.EnableLoadBalancerIPAM)
	flags.Bool(option.EnableCiliumNodeConfig, defaultConfig.EnableCiliumNodeConfig, "Enable CiliumNodeConfig")
	flags.MarkHidden(option.EnableCiliumNodeConfig)
}
