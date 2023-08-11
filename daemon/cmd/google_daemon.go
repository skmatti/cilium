package cmd

import (
	"context"
	"fmt"

	"github.com/cilium/cilium/pkg/gke/multinic"
	multinicctrl "github.com/cilium/cilium/pkg/gke/multinic/controller"
	dhcp "github.com/cilium/cilium/pkg/gke/multinic/dhcp"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/node"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/option"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	networkv1 "k8s.io/cloud-provider-gcp/crd/apis/network/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	ctrlClient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/manager"
)

var (
	scheme = runtime.NewScheme()

	multiniclog = logging.DefaultLogger.WithField(logfields.LogSubsys, "multinic")
	sslog       = logging.DefaultLogger.WithField(logfields.LogSubsys, "servicesteering")
)

func init() {
	// The controller runs on every node. Consider performance impact when adding new schemes.
	utilruntime.Must(corev1.AddToScheme(scheme))
	utilruntime.Must(networkv1.AddToScheme(scheme))
}

func (d *Daemon) initGoogleControllers(ctx context.Context) {
	if !option.Config.EnableGoogleMultiNIC { // Add an OR clause here, to check other feature toggles.
		return
	}

	if !d.clientset.IsEnabled() {
		if option.Config.EnableGoogleMultiNIC { // Add an OR clause here, to check other feature toggles.
			log.Fatal("K8s needs to be enabled for multinic support")
		}
		return
	}

	mgr, err := d.initManager()
	if err != nil {
		log.WithError(err).Fatal("Unable to create controller manager")
	}

	// Initialize and wait for multinic client cache to sync
	if option.Config.EnableGoogleMultiNIC {
		if err := d.initMultiNIC(ctx, mgr); err != nil {
			log.WithError(err).Fatal("Unable to init multinic")
		}
	}

	if enableCtrlManager := option.Config.EnableGoogleMultiNIC; enableCtrlManager { // Add an OR clause here, to check other feature toggles.
		// At least one controller is enabled, so start controller manager
		log.Info("Starting google controller manager")
		go func() {
			if err := mgr.Start(ctx); err != nil {
				log.WithError(err).Fatal("failed to run google controller manager")
			}
			log.Info("Stopped google controller manager")
		}()
	}
}

func (d *Daemon) initManager() (manager.Manager, error) {
	mgr, err := ctrl.NewManager(d.clientset.RestConfig(), ctrl.Options{
		Scheme:                scheme,
		MetricsBindAddress:    "0",
		ClientDisableCacheFor: []ctrlClient.Object{&networkv1.NetworkInterface{}},
	})
	if err != nil {
		return nil, err
	}
	return mgr, nil
}

func (d *Daemon) initMultiNIC(ctx context.Context, mgr manager.Manager) error {
	if err := d.UpdateMultiNetworkIPAMAllocators(node.GetAnnotations()); err != nil {
		return fmt.Errorf("failed to initialize multi-network allocators: %v", err)
	}

	if err := (&multinicctrl.NetworkReconciler{
		Client:          mgr.GetClient(),
		EndpointManager: d.endpointManager,
		NodeName:        nodeTypes.GetName(),
		IPAMMgr:         d,
	}).SetupWithManager(mgr); err != nil {
		return fmt.Errorf("failed to setup network controller: %v", err)
	}
	multiniclog.Info("Created Network controller")

	kubeletClient, err := multinic.NewKubeletClient(ctx)
	if err != nil {
		return fmt.Errorf("failed to create kubelet client: %v", err)
	}
	d.multinicClient = multinic.NewK8sClient(mgr.GetClient())
	d.kubeletClient = kubeletClient
	d.dhcpClient = dhcp.NewDHCPClient()
	return nil
}
