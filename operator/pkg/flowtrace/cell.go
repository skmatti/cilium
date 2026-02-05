package flowtrace

import (
	"context"
	"fmt"

	gkenetworkv1client "github.com/GoogleCloudPlatform/gke-networking-api/client/network/clientset/versioned"
	operatorK8s "github.com/cilium/cilium/operator/k8s"
	"github.com/cilium/cilium/operator/pkg/flowtrace/config"
	"github.com/cilium/cilium/operator/pkg/flowtrace/controller"
	"github.com/cilium/cilium/operator/pkg/flowtrace/logging"
	"github.com/cilium/cilium/pkg/datapath/linux/config/defines"
	ftclientset "github.com/cilium/cilium/pkg/gke/client/flowtrace/clientset/versioned"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/hive/cell"
	ctrlRuntime "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/manager"
)

// Cell provides the flow trace functionality.
var Cell = cell.Module(
	"flow-trace",
	"Flow Trace helps debugging connectivity across two endpoints",

	cell.Config(config.DefaultConfig),
	cell.Provide(initFlowTrace),
	cell.Provide(func(clientset k8sClient.Clientset) (ftclientset.Interface, error) {
		if !clientset.IsEnabled() {
			return nil, nil
		}
		return ftclientset.NewForConfig(clientset.RestConfig())
	}),
	cell.Invoke(ftRegister),
)

type ftParams struct {
	cell.In
	Config        config.Config
	ClientSet     k8sClient.Clientset
	OpResources   operatorK8s.Resources
	NetworkClient gkenetworkv1client.Interface
	FTClient      ftclientset.Interface
	Manager       ctrlRuntime.Manager
}

// initFlowTrace initializes the flow-trace module based on the provided configuration.
// It returns a NodeOut with defines if flow trace is enabled.
func initFlowTrace(cfg config.Config) (out struct {
	cell.Out
	defines.NodeOut
}, err error) {
	if cfg.EnableFlowTrace {
		out.NodeDefines = map[string]string{
			"ENABLE_FLOW_TRACE": "1",
		}
	}
	return out, nil
}

// ftRegister registers the flowtrace controller with the controller-runtime manager.
func ftRegister(params ftParams) error {
	if !params.Config.EnableFlowTrace {
		logging.FtLogger.Info("'enable-flow-trace' flag is disabled, skipping FlowTrace controller initialization")
		return nil
	}
	if params.Manager == nil {
		logging.FtLogger.Info("Manager is nil, skipping FlowTrace controller initialization")
		return nil // Should not happen if controllerruntime.Cell is a dependency
	}

	logging.FtLogger.Info("Registering FlowTrace controller with Manager")
	c := controller.NewController(params.ClientSet, params.OpResources, params.NetworkClient, params.FTClient)

	err := params.Manager.Add(manager.RunnableFunc(func(ctx context.Context) error {
		logging.FtLogger.Info("Starting FlowTrace controller via Manager")
		c.Start(ctx)
		// Keep running until context is cancelled
		<-ctx.Done()
		logging.FtLogger.Info("Stopping FlowTrace controller via Manager")
		c.Stop()
		return nil
	}))
	if err != nil {
		return fmt.Errorf("failed to add flowtrace controller to manager: %w", err)
	}
	return nil
}
