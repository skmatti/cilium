package trafficsteering

import (
	"fmt"

	"github.com/cilium/cilium/pkg/gke/client/trafficsteering/clientset/versioned"
	"github.com/cilium/cilium/pkg/gke/trafficsteering/controller"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/promise"
	"github.com/spf13/pflag"
)

var Cell = cell.Module(
	"traffic-steering",
	"Traffic Steering",

	cell.Provide(trafficSteeringClient),
	cell.Config(defaultConfig),
	cell.Invoke(initTrafficSteering),
)

type trafficSteeringParams struct {
	cell.In

	Lifecycle        hive.Lifecycle
	Config           Config
	DaemonConfig     *option.DaemonConfig
	Clientset        k8sClient.Clientset
	TsClient         *versioned.Clientset
	EgressMapPromise promise.Promise[controller.EgressMapInterface]
}

type Config struct {
	EnableTrafficSteering bool
}

var defaultConfig = Config{
	EnableTrafficSteering: false,
}

func (cfg Config) Flags(flags *pflag.FlagSet) {
	flags.Bool(option.EnableTrafficSteering, defaultConfig.EnableTrafficSteering, "Enable google traffic steering functionality.")
	flags.MarkHidden(option.EnableTrafficSteering)
}

func trafficSteeringClient(clientset k8sClient.Clientset) (*versioned.Clientset, error) {
	trafficSteeringClient, err := versioned.NewForConfig(clientset.RestConfig())
	if err != nil {
		return nil, fmt.Errorf("failed to create NodeNetworkPolicy client: %v", err)
	}
	return trafficSteeringClient, nil
}

func initTrafficSteering(params trafficSteeringParams) error {
	if !params.Config.EnableTrafficSteering {
		return nil
	}
	if !params.DaemonConfig.EnableIPv4EgressGateway {
		return fmt.Errorf("traffic steering requires --%s=\"true\"", option.EnableIPv4EgressGateway)
	}

	var c *controller.Controller
	params.Lifecycle.Append(hive.Hook{
		OnStart: func(ctx hive.HookContext) error {
			em, err := params.EgressMapPromise.Await(ctx)
			if err != nil {
				return fmt.Errorf("failed to get egress map: %v", err)
			}

			c, err := controller.NewController(params.Clientset, params.TsClient, em)
			if err != nil {
				return fmt.Errorf("failed to instantiate traffic steering controller %v", err)
			}
			return c.Start(ctx)
		},
		OnStop: func(_ hive.HookContext) error {
			if c != nil {
				c.Stop()
			}
			return nil
		},
	})
	return nil
}
