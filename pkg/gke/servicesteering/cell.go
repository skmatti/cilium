package servicesteering

import (
	"context"
	"fmt"

	agentK8s "github.com/cilium/cilium/daemon/k8s"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/gke/servicesteering/config"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/maps/sfc"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/hive/cell"
)

var Cell = cell.Module(
	"service-steering",
	"Service Steering",

	config.Cell,
	cell.Invoke(initServiceSteering),
	metrics.Metric(newMetrics),
)

type params struct {
	cell.In

	Lifecycle cell.Lifecycle
	Clientset k8sClient.Clientset
	Config    config.Config
	EpManager endpointmanager.EndpointManager
	Resources agentK8s.Resources
	Metrics   sfcMetrics
}

func initServiceSteering(p params) error {
	if !p.Config.EnableGoogleServiceSteering {
		return nil
	}
	config.GlobalConfig = p.Config
	if err := sfc.SelectMap.OpenOrCreate(); err != nil {
		return fmt.Errorf("failed to open/create %s map: %v", sfc.SelectMapName, err)
	}
	sfc.InitFlowMap(p.Config.FlowMapEntries)
	if err := sfc.FlowMapAny4.OpenOrCreate(); err != nil {
		return fmt.Errorf("failed to open/create %s map: %v", sfc.FlowMapAny4Name, err)
	}
	if err := sfc.PathMap.OpenOrCreate(); err != nil {
		return fmt.Errorf("failed to open/create %s map: %v", sfc.PathMapName, err)
	}
	initDataPathOption()

	if !p.Clientset.IsEnabled() {
		return nil
	}

	mgrCtx, cancel := context.WithCancel(context.Background())
	p.Lifecycle.Append(cell.Hook{
		OnStart: func(_ cell.HookContext) error {
			return runServiceSteeringController(mgrCtx, p)
		},
		OnStop: func(hc cell.HookContext) error {
			cancel()
			return nil
		},
	})

	return nil
}
