package config

import (
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/hive/cell"
	"github.com/spf13/pflag"
)

const (
	enableFlag         = "enable-google-service-steering"
	flowMapEntriesFlag = "bpf-sfc-flow-map-max"
)

var Cell = cell.Config(defaultConfig)

var (
	// Used when config can't be injected by the Hive
	GlobalConfig = defaultConfig
)

type Config struct {
	EnableGoogleServiceSteering bool
	FlowMapEntries              int `mapstructure:"bpf-sfc-flow-map-max"`
}

var defaultConfig = Config{
	EnableGoogleServiceSteering: false,
	FlowMapEntries:              option.CTMapEntriesGlobalTCPDefault,
}

func (cfg Config) Flags(flags *pflag.FlagSet) {
	flags.Bool(enableFlag, defaultConfig.EnableGoogleServiceSteering, "Enable Service Steering support")
	flags.MarkHidden(enableFlag)
	flags.Int(flowMapEntriesFlag, defaultConfig.FlowMapEntries, "Maximum number of entries in the sfcflow BPF map")
	flags.MarkHidden(flowMapEntriesFlag)
}

func Enabled() bool {
	return GlobalConfig.EnableGoogleServiceSteering
}
