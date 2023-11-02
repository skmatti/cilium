package disablesourcevalidation

import (
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
	"github.com/spf13/pflag"
	networkv1 "k8s.io/cloud-provider-gcp/crd/apis/network/v1"
)

var (
	// config holds the global configuration which is set during module initialization.
	config = defaultConfig
	log    = logging.DefaultLogger.WithField(logfields.LogSubsys, "disable-source-validation")
)

var Cell = cell.Module(
	"disable-source-validation",
	"Disable Source Validation",

	cell.Config(defaultConfig),
	cell.Invoke(func(c Config) { config = c }),
)

type Config struct {
	AllowDisableSourceIPValidation  bool
	AllowDisableSourceMACValidation bool
}

var defaultConfig = Config{
	AllowDisableSourceIPValidation:  false,
	AllowDisableSourceMACValidation: false,
}

func (cfg Config) Flags(flags *pflag.FlagSet) {
	flags.Bool(option.AllowDisableSourceIPValidation, defaultConfig.AllowDisableSourceIPValidation, "Allow disabling source IP validation for multi-nic endpoints.")
	flags.MarkHidden(option.AllowDisableSourceIPValidation)

	flags.Bool(option.AllowDisableSourceMACValidation, defaultConfig.AllowDisableSourceMACValidation, "Allow disabling source MAC validation for multi-nic endpoints.")
	flags.MarkHidden(option.AllowDisableSourceMACValidation)
}

func DisableSourceIPValidation(pod string, annotations map[string]string) bool {
	if !config.AllowDisableSourceIPValidation {
		return false
	}
	if annotations[networkv1.DisableSourceIPValidationAnnotationKey] == networkv1.DisableSourceIPValidationAnnotationValTrue {
		log.Infof("Disabling source IP validation for pod %s", pod)
		return true
	}
	return false
}

func DisableSourceMACValidation(pod string, annotations map[string]string) bool {
	if !config.AllowDisableSourceMACValidation {
		return false
	}

	if annotations[networkv1.DisableSourceMACValidationAnnotationKey] == networkv1.DisableSourceMACValidationAnnotationValTrue {
		log.Infof("Disabling source MAC validation for pod %s", pod)
		return true
	}
	return false
}
