package remotenode

import (
	"fmt"

	"github.com/cilium/cilium/pkg/gke/client/remotenode/clientset/versioned"
	"github.com/cilium/cilium/pkg/gke/remotenode/controller"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/promise"
	"github.com/cilium/cilium/pkg/wireguard/agent"
)

var Cell = cell.Module(
	"remote-node",
	"Remote Node",

	cell.Provide(remoteNodeClient),
	cell.Invoke(initRemoteNode),
)

type remoteNodeParams struct {
	cell.In
	Lifecycle      hive.Lifecycle
	DaemonConfig   *option.DaemonConfig
	Clientset      client.Clientset
	RNClient       *versioned.Clientset
	WireguardAgent *agent.Agent
	IpCachePromise promise.Promise[controller.IPCache]
}

func remoteNodeClient(clientset client.Clientset) (*versioned.Clientset, error) {
	remoteNodeClient, err := versioned.NewForConfig(clientset.RestConfig())
	if err != nil {
		return nil, fmt.Errorf("failed to create RemoteNode client: %v", err)
	}
	return remoteNodeClient, nil
}

func initRemoteNode(params remoteNodeParams) error {
	if !params.DaemonConfig.EnableWireguard {
		return nil
	}
	var c *controller.Controller
	params.Lifecycle.Append(hive.Hook{
		OnStart: func(ctx hive.HookContext) error {
			ic, err := params.IpCachePromise.Await(ctx)
			if err != nil {
				return fmt.Errorf("failed to get ipcache: %v", err)
			}
			c := controller.NewController(params.RNClient, params.WireguardAgent, ic)
			return c.Start(ctx)
		},
		OnStop: func(hc hive.HookContext) error {
			if c != nil {
				c.Stop()
			}
			return nil
		},
	})
	return nil
}
