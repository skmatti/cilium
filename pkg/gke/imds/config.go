package imds

import (
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/hive/cell"
	"github.com/spf13/pflag"
)

var (
	// Used when config can't be injected by the Hive
	GlobalConfig = defaultConfig
)

var Cell = cell.Module(
	"imds",
	"IMDS",

	cell.Config(defaultConfig),
	cell.Invoke(func(config Config) { GlobalConfig = config }),
)

// Config struct used to gate OSS features that otherwise have no means to be disabled
type Config struct {
	// AllowIMDSAccessInHostNSOnly adds bpf logic that will block non-hostnetwork
	// pods from accessing IMDS at 169.254.169.254.
	AllowIMDSAccessInHostNSOnly bool
}

var defaultConfig = Config{
	AllowIMDSAccessInHostNSOnly: false,
}

func (cfg Config) Flags(flags *pflag.FlagSet) {
	flags.Bool(option.AllowIMDSAccessInHostNSOnly, defaultConfig.AllowIMDSAccessInHostNSOnly, "AllowIMDSAccessInHostNSOnly adds bpf logic that will block non-hostnetwork")
	flags.MarkHidden(option.AllowIMDSAccessInHostNSOnly)
}
