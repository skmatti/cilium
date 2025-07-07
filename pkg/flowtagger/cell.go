package flowtagger

import (
	"fmt"

	"github.com/cilium/cilium/pkg/flowtagger/controller"
	"github.com/cilium/cilium/pkg/flowtagger/logging"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/client/clientset/versioned"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/promise"
	"github.com/cilium/hive/cell"
	"github.com/spf13/pflag"
)

var Cell = cell.Module(
	"flow-tagger",
	"Flow Tagger",
	cell.Provide(flowTaggerClient),
	cell.Config(defaultConfig),
	cell.Provide(flowTaggerRegister),
	// because of hive's lazy instantiation, requesting
	// flowtagger controller to force the instantiation
	cell.Invoke(func(_ promise.Promise[*controller.Controller]) {}),
)

type flowTaggerParams struct {
	cell.In

	Lifecycle cell.Lifecycle
	Config    Config
	ClientSet k8sClient.Clientset
	FTClient  *versioned.Clientset
}

type Config struct {
	EnableGoogleIPOptionTracing bool `mapstructure:"enable-ip-option-tracing"`
}

var defaultConfig = Config{
	EnableGoogleIPOptionTracing: false,
}

func (cfg Config) Flags(flags *pflag.FlagSet) {
	flags.Bool(option.EnableGoogleIPOptionTracing, defaultConfig.EnableGoogleIPOptionTracing, "Enable Google IP Option Tracing")
	flags.MarkHidden(option.EnableGoogleIPOptionTracing)
}

func flowTaggerClient(clientset k8sClient.Clientset) (*versioned.Clientset, error) {
	if !clientset.IsEnabled() {
		return nil, nil
	}

	ftClient, err := versioned.NewForConfig(clientset.RestConfig())
	if err != nil {
		return nil, fmt.Errorf("create flowtagger client: %v", err)
	}
	return ftClient, nil
}

func flowTaggerRegister(params flowTaggerParams) promise.Promise[*controller.Controller] {
	flowtaggerResolver, flowtaggerPromise := promise.New[*controller.Controller]()
	if !params.Config.EnableGoogleIPOptionTracing {
		logging.FtLogger.Info("'enable-ip-option-tracing' flag is disabled, skipping flowtagger controller initialization")
		flowtaggerResolver.Resolve(nil)
		return flowtaggerPromise
	}

	var c *controller.Controller
	params.Lifecycle.Append(cell.Hook{
		OnStart: func(ctx cell.HookContext) error {
			c = controller.NewController(params.ClientSet, params.FTClient)
			flowtaggerResolver.Resolve(c)
			c.Start(ctx)
			return nil
		},
		OnStop: func(ctx cell.HookContext) error {
			if c != nil {
				c.Stop()
			}
			return nil
		},
	})
	return flowtaggerPromise
}
