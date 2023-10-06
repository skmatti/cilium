package networklogging

import (
	"fmt"

	"github.com/cilium/cilium/pkg/gke/client/networklogging/clientset/versioned"
	gkeflow "github.com/cilium/cilium/pkg/gke/flow"
	"github.com/cilium/cilium/pkg/gke/networklogging/controller"
	"github.com/cilium/cilium/pkg/gke/networklogging/policylogger"
	"github.com/cilium/cilium/pkg/gke/networkpolicy/metrics"
	cilium_api_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_networkingv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/networking/v1"
	metric "github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/hive/cell"
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

	Lifecycle    cell.Lifecycle
	DaemonConfig *option.DaemonConfig
	Clientset    k8sClient.Clientset
	NLClient     *versioned.Clientset
	FlowPlugin   gkeflow.FlowPlugin

	Namespace                        resource.Resource[*slim_corev1.Namespace]
	NetworkPolicies                  resource.Resource[*slim_networkingv1.NetworkPolicy]
	CiliumNetworkPolicies            resource.Resource[*cilium_api_v2.CiliumNetworkPolicy]
	CiliumClusterwideNetworkPolicies resource.Resource[*cilium_api_v2.CiliumClusterwideNetworkPolicy]
	MetricsRegistry                  *metric.Registry
}

func netpolLoggingClient(clientset k8sClient.Clientset) (*versioned.Clientset, error) {
	if !clientset.IsEnabled() {
		return nil, nil
	}

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

	var c *controller.Controller
	params.Lifecycle.Append(cell.Hook{
		OnStart: func(ctx cell.HookContext) error {
			nsStore, err := params.Namespace.Store(ctx)
			if err != nil {
				return fmt.Errorf("get Namespace store: %v", err)
			}
			npStore, err := params.NetworkPolicies.Store(ctx)
			if err != nil {
				return fmt.Errorf("get NetworkPolicies store: %v", err)
			}

			sg := &policylogger.Stores{
				NamespaceStore:     nsStore,
				NetworkPolicyStore: npStore,
			}

			if params.DaemonConfig.EnableCiliumNetworkPolicy {
				cnpStore, err := params.CiliumNetworkPolicies.Store(ctx)
				if err != nil {
					return fmt.Errorf("get CiliumNetworkPolicies store: %v", err)
				}
				sg.CiliumNetworkPolicyStore = cnpStore
			}
			if params.DaemonConfig.EnableCiliumClusterwideNetworkPolicy {
				ccnpStore, err := params.CiliumClusterwideNetworkPolicies.Store(ctx)
				if err != nil {
					return fmt.Errorf("get CiliumClusterwideNetworkPolicies store: %v", err)
				}
				sg.CiliumClusterwideNetworkPolicyStore = ccnpStore
			}

			c = controller.NewController(params.Clientset, params.NLClient, params.FlowPlugin.Dispatcher, nil, sg, params.MetricsRegistry)
			c.Start(ctx)
			return nil
		},
		OnStop: func(hc cell.HookContext) error {
			c.Stop()
			return nil
		},
	})
}
