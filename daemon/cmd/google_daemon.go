package cmd

import (
	"context"
	"fmt"
	"time"

	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/gke/multinic"
	multinicctrl "github.com/cilium/cilium/pkg/gke/multinic/controller"
	dhcp "github.com/cilium/cilium/pkg/gke/multinic/dhcp"
	"github.com/cilium/cilium/pkg/gke/servicesteering"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/node"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/option"
	ssv1 "gke-internal.googlesource.com/anthos-networking/apis/v2/service-steering/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	networkv1 "k8s.io/cloud-provider-gcp/crd/apis/network/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
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

func (d *Daemon) initGoogleModulesBeforeEndpointRestore(ctx context.Context) {
	if option.Config.EnableGoogleServiceSteering {
		if err := servicesteering.InitDataPathOption(ctx); err != nil {
			log.WithError(err).Fatal("Error while initializing service steering data path flag")
		}
	}
}

func (d *Daemon) initGoogleControllers(ctx context.Context, endpoints []*endpoint.Endpoint) {
	if !option.Config.EnableGoogleMultiNIC && !option.Config.EnableGoogleServiceSteering { // Add an OR clause here, to check other feature toggles.
		return
	}

	if !d.clientset.IsEnabled() {
		if option.Config.EnableGoogleMultiNIC || option.Config.EnableGoogleServiceSteering { // Add an OR clause here, to check other feature toggles.
			log.Fatal("K8s needs to be enabled for multinic and service-steering support")
		}
		return
	}

	mgr, err := d.initManager()
	if err != nil {
		log.WithError(err).Fatal("Unable to create controller manager")
	}

	// Initialize and wait for multinic client cache to sync
	if option.Config.EnableGoogleMultiNIC {
		if err := d.initMultiNIC(ctx, mgr, endpoints); err != nil {
			log.WithError(err).Fatal("Unable to init multinic")
		}
	}

	// Initialize service steering controllers
	if option.Config.EnableGoogleServiceSteering {
		if err := d.initServiceSteering(ctx, mgr); err != nil {
			log.WithError(err).Fatal("Unable to init service steering")
		}
	}

	if enableCtrlManager := option.Config.EnableGoogleMultiNIC || option.Config.EnableGoogleServiceSteering; enableCtrlManager { // Add an OR clause here, to check other feature toggles.
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
		NewCache:              filteredCache(),
	})
	if err != nil {
		return nil, err
	}
	return mgr, nil
}

func (d *Daemon) initMultiNIC(ctx context.Context, mgr manager.Manager, endpoints []*endpoint.Endpoint) error {
	reconciler := &multinicctrl.NetworkReconciler{
		Client:          mgr.GetClient(),
		EndpointManager: d.endpointManager,
		NodeName:        nodeTypes.GetName(),
		IPAMMgr:         d,
		DeviceMgr:       d,
		Log:             log,
	}
	if err := reconciler.SetupWithManager(mgr); err != nil {
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
	if err := d.setupMultiNetworkingIPAMAllocators(ctx, endpoints); err != nil {
		return fmt.Errorf("failed to initialize multi-network allocators: %v", err)
	}

	// Populates nic-info node annotation
	if option.Config.PopulateGCENICInfo {
		if err := multinic.PopulateNICInfoAnnotation(d.ctx, d.clientset); err != nil {
			log.WithError(err).Fatalf("unable to populate nic annotations, high-perf networks will not work: %v", err)
		}

		node, err := d.clientset.CoreV1().Nodes().Get(ctx, nodeTypes.GetName(), metav1.GetOptions{})
		if err != nil {
			return fmt.Errorf("unable to get Node %s: %v", nodeTypes.GetName(), err)
		}

		if err := reconciler.RestoreDevices(ctx, node); err != nil {
			return fmt.Errorf("unable to reconcile high-perf network state: %v", err)
		}
	}
	return nil
}

func (d *Daemon) initServiceSteering(ctx context.Context, mgr manager.Manager) error {
	if err := (&servicesteering.ServiceSteeringReconciler{
		Client:          mgr.GetClient(),
		Scheme:          mgr.GetScheme(),
		EndpointManager: d.endpointManager,
	}).SetupWithManager(mgr); err != nil {
		return fmt.Errorf("failed to setup service steering controller: %v", err)
	}
	sslog.Info("Created service steering controller")
	return nil
}

// setupMultiNetworkingIPAMAllocators performs the following actions:
// 1. Initialises the IPAM allocators for the networks present on the node that is derived from the node annotations.
// 2. Allocates the IPs associated with the given endpoints inside the allocators created in step 1.
func (d *Daemon) setupMultiNetworkingIPAMAllocators(ctx context.Context, endpoints []*endpoint.Endpoint) error {
	if err := d.UpdateMultiNetworkIPAMAllocators(node.GetAnnotations()); err != nil {
		return fmt.Errorf("failed to initialize multi-network allocators: %v", err)
	}
	if err := d.PreAllocateIPsForRestoredMultiNICEndpoints(endpoints); err != nil {
		return fmt.Errorf("failed to pre-allocate IPs in multinetworking IPAM allocators for restored endpoints: %v", err)
	}
	return nil
}

// filteredCache returns a cache with a ListWatch that's restricted to the desired fields in order
// to reduce memory consumption.
func filteredCache() cache.NewCacheFunc {
	resyncInterval := time.Minute * 10
	return cache.BuilderWithOptions(cache.Options{
		Resync: &resyncInterval,
		SelectorsByObject: cache.SelectorsByObject{
			&networkv1.Network{}: {},
			&corev1.Node{}: {
				Field: fields.SelectorFromSet(fields.Set{"metadata.name": nodeTypes.GetName()}),
			},
			&corev1.Service{}:            servicesteering.FilteredSvcSelector(),
			&ssv1.TrafficSelector{}:      {},
			&ssv1.ServiceFunctionChain{}: {},
		},
	})
}
