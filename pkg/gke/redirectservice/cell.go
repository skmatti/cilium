package redirectservice

import (
	"fmt"

	"github.com/cilium/cilium/pkg/datapath/iptables"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/gke/client/redirectservice/clientset/versioned"
	controller "github.com/cilium/cilium/pkg/gke/redirectservice/controller"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/promise"
	"github.com/cilium/cilium/pkg/redirectpolicy"
	"github.com/cilium/hive/cell"
	"github.com/sirupsen/logrus"
	"github.com/spf13/pflag"
)

var (
	Cell = cell.Module(
		"redirect-service",
		"Redirect Service",

		cell.Config(defaultConfig),
		cell.Invoke(registerRedirectService),
	)
	log = logging.DefaultLogger.WithField(logfields.LogSubsys, "gke-redirect-service-controller")
)

const (
	// LabelNodeLocalDNS is the label of node-local-dns pods.
	LabelNodeLocalDNS = "k8s-app=node-local-dns"

	// EnableRedirectService enables google redirect service for the host
	EnableRedirectService = "enable-redirect-service"
)

type redirectServiceManager struct {
	redirectPolicyManager     controller.RedirectPolicyManager
	redirectServiceController *controller.Controller
}

var _ endpointmanager.Subscriber = &redirectServiceManager{}

type redirectServiceParams struct {
	cell.In

	Lifecycle       cell.Lifecycle
	Clientset       k8sClient.Clientset
	Config          Config
	EndpointManager endpointmanager.EndpointManager
	RpmPromise      promise.Promise[controller.RedirectPolicyManager]
	IptablesManager *iptables.Manager
}

type Config struct {
	EnableRedirectService bool
}

var defaultConfig = Config{
	EnableRedirectService: false,
}

func (cfg Config) Flags(flags *pflag.FlagSet) {
	flags.Bool(EnableRedirectService, defaultConfig.EnableRedirectService, fmt.Sprintf("Enable Redirect Service. Requires %q to be enabled.", EnableRedirectService))
	flags.MarkHidden(EnableRedirectService)
}

// EndpointDeleted is a callback to satisfy EndpointManager.Subscriber,
func (rsm *redirectServiceManager) EndpointDeleted(ep *endpoint.Endpoint, conf endpoint.DeleteConfig) {
	if !ep.HasLabels(labels.NewLabelsFromModel([]string{fmt.Sprintf("%s:%s", labels.LabelSourceK8s, LabelNodeLocalDNS)})) {
		// Not a node local DNS pod
		return
	}
	if pod := ep.GetPod(); pod != nil {
		rsm.redirectPolicyManager.OnDeletePod(pod)
		return
	}

	if !ep.IPv4.IsValid() {
		log.WithField(logfields.IPv4, ep.IPv4).Errorf("endpoint IP is invalid")
		return
	}

	epMetadata := redirectpolicy.DeletedEndpointMetadata{
		Name:      ep.K8sPodName,
		Namespace: ep.K8sNamespace,
		Labels:    ep.OpLabels.AllLabels().K8sStringMap(),
		IP:        ep.IPv4.String(),
	}

	log.WithFields(logrus.Fields{
		logfields.K8sPodName: epMetadata.Name,
		logfields.IPv4:       epMetadata.IP,
	}).Info("Queued endpoint delete for NLD pod.")
	if rsm.redirectServiceController != nil {
		rsm.redirectServiceController.DelNoTrackForQueuedEndpoint(epMetadata)
	}
}

// EndpointCreated is a callback to satisfy EndpointManager.Subscriber.
func (rsm *redirectServiceManager) EndpointCreated(ep *endpoint.Endpoint) {}

// EndpointRestored is a callback to satisfy EndpointManager.Subscriber.
func (rsm *redirectServiceManager) EndpointRestored(ep *endpoint.Endpoint) {}

func registerRedirectService(params redirectServiceParams) error {
	if !params.Config.EnableRedirectService || !params.Clientset.IsEnabled() {
		return nil
	}

	redirectServiceClient, err := versioned.NewForConfig(params.Clientset.RestConfig())
	if err != nil {
		return fmt.Errorf("failed to create RedirectService client: %v", err)
	}

	var c *controller.Controller
	params.Lifecycle.Append(cell.Hook{
		OnStart: func(ctx cell.HookContext) error {
			redirectPolicyManager, err := params.RpmPromise.Await(ctx)
			if err != nil {
				return fmt.Errorf("failed to get redirect policy manager: %v", err)
			}

			redirectServiceManager := &redirectServiceManager{
				redirectPolicyManager: redirectPolicyManager,
			}

			params.EndpointManager.Subscribe(redirectServiceManager)
			if err := params.IptablesManager.Start(ctx); err != nil {
				return fmt.Errorf("start IP tables manager: %v", err)
			}

			c, err := controller.NewController(params.Clientset, params.Clientset.Slim(), redirectServiceClient, redirectPolicyManager, params.IptablesManager)
			if err != nil {
				log.Errorf("Error instantiating redirect service controller %v", err)
				return err
			}
			redirectServiceManager.redirectServiceController = c
			go c.Start()
			return nil
		},
		OnStop: func(_ cell.HookContext) error {
			if c != nil {
				c.Stop()
			}
			return nil
		},
	})

	return nil
}
