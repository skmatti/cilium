package multinic

import (
	"context"

	agentK8s "github.com/cilium/cilium/daemon/k8s"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/gke/multinic/multinicconfig"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/hive/cell"
)

var Cell = cell.Module(
	"google-multinetworking",
	"Google Multinetworking",
	cell.Invoke(initMultinetworking),
)

type params struct {
	cell.In

	Lifecycle cell.Lifecycle
	Clientset k8sClient.Clientset
	Config    multinicconfig.Config
	EpManager endpointmanager.EndpointManager
	Resources agentK8s.Resources
}

func initMultinetworking(p params) error {
	if !p.Config.EnableGoogleMultiNIC {
		return nil
	}
	multinicconfig.GlobalConfig = p.Config
	if !p.Clientset.IsEnabled() {
		return nil
	}

	_, cancel := context.WithCancel(context.Background())
	p.Lifecycle.Append(cell.Hook{
		OnStart: func(_ cell.HookContext) error {
			// TODO(b/336614270) - Move MN to hive cell
			return nil
		},
		OnStop: func(hc cell.HookContext) error {
			cancel()
			return nil
		},
	})

	return nil
}
