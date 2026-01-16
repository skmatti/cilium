package config

import (
	"github.com/spf13/pflag"
)

const (
	// EnableFlowTrace is the name of the option to enable flow trace.
	EnableFlowTrace = "enable-flow-trace"
)

// Config is the configuration for the flow trace functionality.
type Config struct {
	EnableFlowTrace bool `mapstructure:"enable-flow-trace"`
}

// defaultConfig is the default configuration for the flow trace functionality.
var DefaultConfig = Config{
	EnableFlowTrace: false,
}

// Flags implements cell.Flagger and registers the configuration flags for the flow-trace module.
func (cfg Config) Flags(flags *pflag.FlagSet) {
	flags.Bool(EnableFlowTrace, cfg.EnableFlowTrace, "Enable Flow Trace")
	flags.MarkHidden(EnableFlowTrace)
}
