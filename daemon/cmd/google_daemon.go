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
	"github.com/cilium/cilium/pkg/k8s"
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
	"sigs.k8s.io/controller-runtime/pkg/client"
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
	utilruntime.Must(ssv1.AddToScheme(scheme))
}

func (d *Daemon) initGoogleControllers(ctx context.Context, endpoints []*endpoint.Endpoint) {
	if !k8s.IsEnabled() {
		if option.Config.EnableGoogleMultiNIC || option.Config.EnableGoogleServiceSteering {
			log.Fatal("K8s needs to be enabled for multinic and service-steering support")
		}
		return
	}

	mgr, err := initManager()
	if err != nil {
		log.WithError(err).Fatal("Unable to create controller manager")
	}
	if option.Config.EnableGoogleServiceSteering {
		crdsExist, err := servicesteering.CRDsExist(mgr.GetRESTMapper())
		if err != nil {
			sslog.WithError(err).Fatal("Unable to probe for service steering CRDs")
		}
		if !crdsExist {
			sslog.Warn("Service steering CRDs are missing, disabling the feature")
			option.Config.EnableGoogleServiceSteering = false
		}
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

	if enableCtrlManager := option.Config.EnableGoogleMultiNIC || option.Config.EnableGoogleServiceSteering; enableCtrlManager {
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

func initManager() (manager.Manager, error) {
	kubeConfig, err := k8s.CreateConfig()
	if err != nil {
		return nil, err
	}
	mgr, err := ctrl.NewManager(kubeConfig, ctrl.Options{
		Scheme:                scheme,
		MetricsBindAddress:    "0",
		NewCache:              filteredCache(),
		ClientDisableCacheFor: []client.Object{&networkv1.NetworkInterface{}},
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
		if err := multinic.PopulateNICInfoAnnotation(d.ctx, k8s.Client()); err != nil {
			log.WithError(err).Fatalf("unable to populate nic annotations, high-perf networks will not work")
		}
		node, err := k8s.Client().CoreV1().Nodes().Get(ctx, nodeTypes.GetName(), metav1.GetOptions{})
		if err != nil {
			return fmt.Errorf("unable to get Node %s: %v", nodeTypes.GetName(), err)
		}

		if err := reconciler.RestoreDevices(ctx, node, log); err != nil {
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
			&corev1.Service{}:            servicesteering.FilteredSvcSelector(),
			&ssv1.TrafficSelector{}:      {},
			&ssv1.ServiceFunctionChain{}: {},
			&networkv1.Network{}:         {},
			&corev1.Node{}: {
				Field: fields.SelectorFromSet(fields.Set{"metadata.name": nodeTypes.GetName()}),
			},
		},
	})
}
