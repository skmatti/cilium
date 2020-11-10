package redirectservice

import (
	"fmt"

	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/gke/client/redirectservice/clientset/versioned"
	controller "github.com/cilium/cilium/pkg/gke/redirectservice/controller"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/promise"
	"github.com/spf13/pflag"
)

var (
	Cell = cell.Module(
		"redirect-service",
		"Redirect Service",

		cell.Config(defaultConfig),
		cell.Provide(redirectServiceClient),
		cell.Invoke(registerRedirectService),
	)
	log = logging.DefaultLogger.WithField(logfields.LogSubsys, "gke-redirect-service-controller")
)

const (
	// LabelNodeLocalDNS is the label of node-local-dns pods.
	LabelNodeLocalDNS = "k8s-app=node-local-dns"
)

type redirectServiceManager struct {
	redirectPolicyManager controller.RedirectPolicyManager
}

type redirectServiceParams struct {
	cell.In

	Lifecycle             hive.Lifecycle
	Clientset             k8sClient.Clientset
	Config                Config
	RedirectServiceClient *versioned.Clientset
	RpmPromise            promise.Promise[controller.RedirectPolicyManager]
	EmPromise             promise.Promise[*endpointmanager.EndpointManager]
}

type Config struct {
	EnableRedirectService bool
}

var defaultConfig = Config{
	EnableRedirectService: false,
}

func (cfg Config) Flags(flags *pflag.FlagSet) {
	flags.Bool(option.EnableRedirectService, defaultConfig.EnableRedirectService, fmt.Sprintf("Enable Redirect Service. Requires %q to be enabled.", option.EnableRedirectService))
	flags.MarkHidden(option.EnableRedirectService)
}

// EndpointDeleted is a callback to satisfy EndpointManager.Subscriber,
func (rsm *redirectServiceManager) EndpointDeleted(ep *endpoint.Endpoint, conf endpoint.DeleteConfig) {
	if ep.GetPod() != nil && ep.HasLabels(labels.NewLabelsFromModel([]string{fmt.Sprintf("%s:%s", labels.LabelSourceK8s, LabelNodeLocalDNS)})) {
		rsm.redirectPolicyManager.OnDeletePod(ep.GetPod())
	}
}

// EndpointCreated is a callback to satisfy EndpointManager.Subscriber.
func (rsm *redirectServiceManager) EndpointCreated(ep *endpoint.Endpoint) {}

func redirectServiceClient(clientset k8sClient.Clientset) (*versioned.Clientset, error) {
	redirectServiceClient, err := versioned.NewForConfig(clientset.RestConfig())
	if err != nil {
		return nil, fmt.Errorf("failed to create RedirectService client: %v", err)
	}
	return redirectServiceClient, nil
}

func registerRedirectService(params redirectServiceParams) {
	if !(params.Config.EnableRedirectService) {
		return
	}

	var c *controller.Controller
	params.Lifecycle.Append(hive.Hook{
		OnStart: func(ctx hive.HookContext) error {
			redirectPolicyManager, err := params.RpmPromise.Await(ctx)
			if err != nil {
				return fmt.Errorf("failed to get redirect policy manager: %v", err)
			}

			endpointManager, err := params.EmPromise.Await(ctx)
			if err != nil {
				return fmt.Errorf("failed to get endpoint manager: %v", err)
			}

			redirectServiceManager := &redirectServiceManager{
				redirectPolicyManager: redirectPolicyManager,
			}

			endpointManager.Subscribe(redirectServiceManager)

			c, err := controller.NewController(params.Clientset, params.RedirectServiceClient, redirectPolicyManager)
			if err != nil {
				log.Errorf("Error instantiating redirect service controller %v", err)
				return err
			}
			go c.Start()
			return nil
		},
		OnStop: func(_ hive.HookContext) error {
			if c != nil {
				c.Stop()
			}
			return nil
		},
	})
}
