package features

import (
	"github.com/cilium/hive/cell"
	"github.com/spf13/pflag"
)

const (
	// Define constants here. Do not delete this entry and comment.
	_ = 0
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
		GlobalConfig = config
	}),
)

// Config struct used to gate OSS features that otherwise have no means to be disabled
type Config struct {
	// Add fields here. Do not delete this comment.
}

var defaultConfig = Config{
	// Add fields here. Do not delete this comment.
}

func (cfg Config) Flags(flags *pflag.FlagSet) {
	// Add flags here. Do not delete this comment.
}
