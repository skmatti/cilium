package networklogging

import (
	"fmt"

	fqdnv1alpha1 "github.com/cilium/cilium/pkg/gke/apis/fqdnnetworkpolicy/v1alpha1"
	fqdnversioned "github.com/cilium/cilium/pkg/gke/client/fqdnnetworkpolicy/clientset/versioned"
	"github.com/cilium/cilium/pkg/gke/client/networklogging/clientset/versioned"
	gkeflow "github.com/cilium/cilium/pkg/gke/flow"
	"github.com/cilium/cilium/pkg/gke/fqdnnetworkpolicy"
	"github.com/cilium/cilium/pkg/gke/networklogging/controller"
	"github.com/cilium/cilium/pkg/gke/networklogging/policylogger"
	"github.com/cilium/cilium/pkg/gke/networkpolicy/metrics"
	cilium_api_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_networkingv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/networking/v1"
	"github.com/cilium/cilium/pkg/k8s/utils"
	metric "github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/hive/cell"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var Cell = cell.Module(
	"network-policy-logging",
	"Network Policy Logging",

	cell.Provide(fqdnNetworkPolicyResources),
	cell.Provide(netpolLoggingClient),
	cell.Invoke(registerNetpolLogging),

	gkeflow.Cell,
	metrics.Cell,
)

func fqdnNetworkPolicyResources(lc cell.Lifecycle, config fqdnnetworkpolicy.Config, fqdnClient fqdnversioned.Interface) (resource.Resource[*fqdnv1alpha1.FQDNNetworkPolicy], error) {
	if !config.EnableFQDNNetworkPolicy {
		return nil, nil
	}
	// This cascades the `!clientset.IsEnabled()` result from the client provier.
	if fqdnClient == nil {
		return nil, nil
	}
	return resource.New[*fqdnv1alpha1.FQDNNetworkPolicy](
		lc,
		utils.ListerWatcherWithModifier(
			utils.ListerWatcherFromTyped[*fqdnv1alpha1.FQDNNetworkPolicyList](fqdnClient.NetworkingV1alpha1().FQDNNetworkPolicies("")),
			func(lo *v1.ListOptions) {}),
	), nil
}

type netpolLoggingParams struct {
	cell.In

	Lifecycle    cell.Lifecycle
	DaemonConfig *option.DaemonConfig
	Clientset    k8sClient.Clientset
	NLClient     *versioned.Clientset
	FlowPlugin   gkeflow.FlowPlugin
	FQDNClient   fqdnversioned.Interface
	FQDNConfig   fqdnnetworkpolicy.Config

	Namespace                        resource.Resource[*slim_corev1.Namespace]
	NetworkPolicies                  resource.Resource[*slim_networkingv1.NetworkPolicy]
	FQDNNetworkPolicies              resource.Resource[*fqdnv1alpha1.FQDNNetworkPolicy]
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

			if params.FQDNConfig.EnableFQDNNetworkPolicy {
				fqdnStore, err := params.FQDNNetworkPolicies.Store(ctx)
				if err != nil {
					return fmt.Errorf("get FQDNNetworkPolicies store: %v", err)
				}
				sg.FQDNNetworkPolicyStore = fqdnStore
			}

			c = controller.NewController(params.Clientset, params.NLClient, params.FlowPlugin.Dispatcher, sg, params.MetricsRegistry)
			c.Start(ctx)
			return nil
		},
		OnStop: func(hc cell.HookContext) error {
			c.Stop()
			return nil
		},
	})
}
