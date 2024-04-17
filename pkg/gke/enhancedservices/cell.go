package enhancedservices

import (
	"context"
	"fmt"

	"github.com/cilium/cilium/pkg/gke/enhancedservices/controller"
	"github.com/cilium/cilium/pkg/gke/eventcache"
	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/k8s/client"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/hive/cell"
	"github.com/spf13/pflag"
)

var Cell = cell.Module(
	"enhanced-services",
	"Enhanced Services",
	cell.Config(defaultConfig),
	cell.Invoke(initEnhancedServices),
	cell.Provide(HybridCache),
)

type enhancedServicesParams struct {
	cell.In

	Lifecycle              cell.Lifecycle
	Clientset              k8sClient.Clientset
	Config                 Config
	EnhancedServicesClient client.Clientset
	MetricsRegistry        *metrics.Registry
}

type Config struct {
	EnableEnhancedServices bool
	TrafficDirectorMesh    string
}

var defaultConfig = Config{
	EnableEnhancedServices: false,
}

func (cfg Config) Flags(flags *pflag.FlagSet) {
	flags.Bool(option.EnableEnhancedServices, defaultConfig.EnableEnhancedServices, "Enable google enhanced services.")
	flags.String(option.TrafficDirectorMesh, "", "The name of the Traffic Director mesh used for google advanced service route.")
	flags.MarkHidden(option.EnableEnhancedServices)
	flags.MarkHidden(option.TrafficDirectorMesh)
}

func HybridCache(p enhancedServicesParams) k8s.HybridCacheInterface {
	if !p.Config.EnableEnhancedServices {
		return nil
	}
	hybridCache := eventcache.New()
	hybridCache.InitMetrics(p.MetricsRegistry)
	hybridCache.Start()
	k8s.HybridCache = hybridCache
	return hybridCache
}

func initEnhancedServices(params enhancedServicesParams, _ k8s.HybridCacheInterface) error {
	if !params.Config.EnableEnhancedServices {
		return nil
	}

	var c *controller.XDSController
	ctx, cancel := context.WithCancel(context.Background())
	params.Lifecycle.Append(cell.Hook{
		OnStart: func(_ cell.HookContext) error {
			c, err := controller.NewXDSController(params.Config.TrafficDirectorMesh)
			if err != nil {
				return fmt.Errorf("failed to instantiate GKE xDS controller %v", err)
			}
			if err := c.Start(ctx); err != nil {
				return err
			}
			return nil
		},
		OnStop: func(_ cell.HookContext) error {
			if c != nil {
				c.Stop()
			}
			cancel()
			return nil
		},
	})
	return nil
}
