package pip

import (
	"github.com/cilium/cilium/pkg/maps/pip"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/hive/cell"
	"github.com/spf13/pflag"
)

var globalPersistentIPConfig = defaultConfig

var Cell = cell.Module(
	"persistent-ip-config",
	"Persistent IP Config",

	cell.Config(defaultConfig),
	cell.Invoke(initPersistentIP),
)

type Config struct {
	EnableGooglePersistentIP bool `mapstructure:"enable-google-persistent-ip"`
}

var defaultConfig = Config{
	EnableGooglePersistentIP: false,
}

func (cfg Config) Flags(flags *pflag.FlagSet) {
	flags.Bool(option.EnableGooglePersistentIP, defaultConfig.EnableGooglePersistentIP, "Enable google persistent-ip support.")
	flags.MarkHidden(option.EnableGooglePersistentIP)
}

type persistentIPParams struct {
	cell.In

	Config Config
}

func initPersistentIP(params persistentIPParams) error {

	globalPersistentIPConfig = params.Config
	if !params.Config.EnableGooglePersistentIP {
		return nil
	}
	if err := pip.RoutingMap.OpenOrCreate(); err != nil {
		return err
	}

	return nil
}

func GlobalPersistentIPConfig() Config {
	return globalPersistentIPConfig
}
