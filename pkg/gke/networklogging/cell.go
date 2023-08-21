package networklogging

import (
	"fmt"

	"github.com/cilium/cilium/pkg/gke/client/networklogging/clientset/versioned"
	gkeflow "github.com/cilium/cilium/pkg/gke/flow"
	"github.com/cilium/cilium/pkg/gke/networklogging/controller"
	"github.com/cilium/cilium/pkg/gke/networkpolicy/metrics"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/hubble/parser/getters"
	"github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/option"
)

var Cell = cell.Module(
	"network-policy-logging",
	"Network Policy Logging",

	cell.Provide(netpolLoggingClient),
	cell.Invoke(registerNetpolLogging),

	gkeflow.Cell,
	metrics.Cell,
)

type netpolLoggingParams struct {
	cell.In
	Lifecycle    hive.Lifecycle
	DaemonConfig *option.DaemonConfig
	Clientset    client.Clientset
	NLClient     *versioned.Clientset
	FlowPlugin   gkeflow.FlowPlugin
}

func netpolLoggingClient(clientset client.Clientset) (*versioned.Clientset, error) {
	netpolLoggingClient, err := versioned.NewForConfig(clientset.RestConfig())
	if err != nil {
		return nil, fmt.Errorf("create network policy logging client: %v", err)
	}
	return netpolLoggingClient, nil
}

func registerNetpolLogging(params netpolLoggingParams) {
	if !params.DaemonConfig.EnableHubble {
		return
	}
	policyCorrelationOpt := controller.WithHubblePolicyCorrelation(params.DaemonConfig.EnableHubbleCorrelatePolicies)

	var c *controller.Controller
	params.Lifecycle.Append(hive.Hook{
		OnStart: func(ctx hive.HookContext) error {
			hubble, err := params.FlowPlugin.HubblePromise.Await(ctx)
			if err != nil {
				return fmt.Errorf("get hubble server: %v", err)
			}

			endpointGetter, ok := hubble.GetOptions().CiliumDaemon.(getters.EndpointGetter)
			if !ok || endpointGetter == nil {
				return fmt.Errorf("invalid type, expected EndpointGetter, got %T", hubble.GetOptions().CiliumDaemon)
			}

			storeGetter, ok := hubble.GetOptions().CiliumDaemon.(getters.StoreGetter)
			if !ok || storeGetter == nil {
				return fmt.Errorf("invalid type, expected StoreGetter, got %T", hubble.GetOptions().CiliumDaemon)
			}

			c = controller.NewController(params.Clientset, params.NLClient, params.FlowPlugin.Dispatcher, endpointGetter, storeGetter, policyCorrelationOpt)
			c.Start(ctx)
			return nil
		},
		OnStop: func(hc hive.HookContext) error {
			c.Stop()
			return nil
		},
	})
}
