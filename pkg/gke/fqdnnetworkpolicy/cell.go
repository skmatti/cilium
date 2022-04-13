package fqdnnetworkpolicy

import (
	"fmt"
	"log"

	"github.com/cilium/cilium/pkg/gke/client/fqdnnetworkpolicy/clientset/versioned"
	"github.com/cilium/cilium/pkg/gke/fqdnnetworkpolicy/controller"
	"github.com/cilium/cilium/pkg/gke/nodefirewall/types"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/promise"
	"github.com/spf13/pflag"
)

var Cell = cell.Module(
	"fqdn-network-policy",
	"FQDN Network Policy",

	cell.Provide(fqdnClient),
	cell.Config(defaultConfig),
	cell.Invoke(registerFQDNNetPol),
)

type fqdnNetPolParams struct {
	cell.In

	Lifecycle    hive.Lifecycle
	Config       Config
	DaemonConfig *option.DaemonConfig
	FQDNClient   versioned.Interface
	PmPromise    promise.Promise[types.PolicyManager]
}

type Config struct {
	EnableFQDNNetworkPolicy bool
}

var defaultConfig = Config{
	EnableFQDNNetworkPolicy: false,
}

func (cfg Config) Flags(flags *pflag.FlagSet) {
	flags.Bool(option.EnableFQDNNetworkPolicy, defaultConfig.EnableFQDNNetworkPolicy, "Enable FQDN network policy")
	flags.MarkHidden(option.EnableFQDNNetworkPolicy)
}

func fqdnClient(clientset k8sClient.Clientset) (versioned.Interface, error) {
	fqdnClient, err := versioned.NewForConfig(clientset.RestConfig())
	if err != nil {
		return nil, fmt.Errorf("failed to create FQDN client: %v", err)
	}
	return fqdnClient, nil
}

func registerFQDNNetPol(params fqdnNetPolParams) {
	if !params.Config.EnableFQDNNetworkPolicy {
		return
	}
	if !params.DaemonConfig.EnableL7Proxy {
		log.Fatalf(`FQDN Network Policy requires --%s=true`, option.EnableL7Proxy)
	}

	var c *controller.Controller
	params.Lifecycle.Append(hive.Hook{
		OnStart: func(ctx hive.HookContext) error {
			policyManager, err := params.PmPromise.Await(ctx)
			if err != nil {
				return fmt.Errorf("failed to get policy manager: %v", err)
			}

			c = controller.NewController(params.FQDNClient, policyManager)
			return c.Start(ctx)
		},
		OnStop: func(_ hive.HookContext) error {
			if c != nil {
				c.Stop()
			}
			return nil
		},
	})
}
