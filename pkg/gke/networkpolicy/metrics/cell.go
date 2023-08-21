package metrics

import (
	"fmt"

	gkeflow "github.com/cilium/cilium/pkg/gke/flow"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
	"github.com/spf13/pflag"
)

var (
	log = logging.DefaultLogger.WithField(logfields.LogSubsys, "gke-network-policy-metrics")
)

var Cell = cell.Module(
	"network-policy-metrics",
	"Network Policy Metrics",

	cell.Config(defaultConfig),
	cell.Invoke(registerNetpolMetrics),
)

type Config struct {
	DisablePolicyEventCountMetric bool
}

var defaultConfig = Config{
	DisablePolicyEventCountMetric: false,
}

func (cfg Config) Flags(flags *pflag.FlagSet) {
	flags.Bool(option.DisablePolicyEventCountMetric, defaultConfig.DisablePolicyEventCountMetric, "Disable the policy event count metric on this host.")
	flags.MarkHidden(option.DisablePolicyEventCountMetric)
}

func registerNetpolMetrics(lc hive.Lifecycle, flowPlugin gkeflow.FlowPlugin, dc *option.DaemonConfig, config Config) {
	if !dc.EnableHubble {
		return
	}
	if config.DisablePolicyEventCountMetric {
		log.Infof("Not starting network policy metric exporter controller because %q=true", option.DisablePolicyEventCountMetric)
		return
	}

	exporter := newExporter(flowPlugin.Dispatcher)
	lc.Append(hive.Hook{
		OnStart: func(hc hive.HookContext) error {
			log.Info("Starting network policy metric exporter controller")
			if err := exporter.start(); err != nil {
				return fmt.Errorf("start network policy metric exporter controller: %v", err)
			}
			log.Info("Successfully started network policy metric exporter controller")
			return nil
		},
		OnStop: func(hc hive.HookContext) error {
			log.Info("Stopping network policy metric exporter controller")
			exporter.stop()
			return nil
		},
	})
}
