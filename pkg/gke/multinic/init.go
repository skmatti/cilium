package multinic

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/cilium/cilium/pkg/backoff"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/gke/features"
	"github.com/cilium/cilium/pkg/gke/multinic/controller"
	"github.com/cilium/cilium/pkg/gke/multinic/dhcp"
	"github.com/cilium/cilium/pkg/gke/multinic/nic"
	"github.com/cilium/cilium/pkg/gke/multinic/types"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/time"
	"github.com/vishvananda/netlink"
	"golang.org/x/sync/errgroup"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/runtime"
	k8sTypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	networkv1 "github.com/GoogleCloudPlatform/gke-networking-api/apis/network/v1"
	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/endpointmanager"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/statedb"
)

const (
	timeoutWaitForIP = 5 * time.Minute
)

var (
	log = logging.DefaultLogger.WithField(logfields.LogSubsys, "multinic")
)

// Init sets up the controller manager and reconcilers for multinic.
func Init(ctx context.Context, endpointManager endpointmanager.EndpointManager, clientset k8sClient.Clientset, endpoints []*endpoint.Endpoint, mnwIPAMMgr types.MultiNetworkIPAMManager, deviceMgr types.HighPerfDeviceManager, devices statedb.Table[*tables.Device], db *statedb.DB) (K8sClient, *KubeletClient, dhcp.DHCPClient, error) {
	scheme := runtime.NewScheme()
	// The controller runs on every node. Consider performance impact when adding new schemes.
	if err := networkv1.AddToScheme(scheme); err != nil {
		return nil, nil, nil, errors.New("failed to add scheme with network APIs")
	}
	if err := corev1.AddToScheme(scheme); err != nil {
		return nil, nil, nil, errors.New("failed to add scheme with core APIs")
	}

	restConfig := clientset.RestConfig()

	mgr, err := ctrl.NewManager(restConfig, ctrl.Options{
		Scheme:   scheme,
		NewCache: filteredCache(restConfig, scheme),
		Metrics: metricsserver.Options{
			BindAddress: "0",
		},
	})
	if err != nil {
		return nil, nil, nil, fmt.Errorf("create manager: %v", err)
	}
	reconciler := &controller.NetworkReconciler{
		Client:          mgr.GetClient(),
		EndpointManager: endpointManager,
		NodeName:        nodeTypes.GetName(),
		Devices:         devices,
		DB:              db,
		IPAMMgr:         mnwIPAMMgr,
		DeviceMgr:       deviceMgr,
		Log:             log,
	}
	if err := reconciler.SetupWithManager(mgr); err != nil {
		return nil, nil, nil, fmt.Errorf("failed to setup network controller: %v", err)
	}
	log.Info("Starting multinic controller manager")
	go func() {
		if err := mgr.Start(ctx); err != nil {
			log.WithError(err).Fatal("failed to run multinic controller manager")
		}
		log.Info("Stopped multinic controller manager")
	}()

	kubeletClient, err := NewKubeletClient(ctx)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to create kubelet client: %v", err)
	}
	if err := setupMultiNetworkingIPAMAllocators(ctx, mnwIPAMMgr, endpoints); err != nil {
		return nil, nil, nil, fmt.Errorf("failed to initialize multi-network allocators: %v", err)
	}

	// Populates nic-info node annotation
	if features.GlobalConfig.PopulateGCENICInfo {
		if err := populateNICInfoAnnotation(ctx, clientset); err != nil {
			log.WithError(err).Fatalf("unable to populate nic annotations, high-perf networks will not work: %v", err)
		}

		node, err := clientset.CoreV1().Nodes().Get(ctx, nodeTypes.GetName(), metav1.GetOptions{})
		if err != nil {
			return nil, nil, nil, fmt.Errorf("unable to get Node %s: %v", nodeTypes.GetName(), err)
		}

		if err := reconciler.RestoreDevices(ctx, node); err != nil {
			return nil, nil, nil, fmt.Errorf("unable to reconcile high-perf network state: %v", err)
		}
	}

	// Optimization for scalablity.
	// The dumb list call triggers the cache build for GKENetworkParamSet.
	// Without this, the cache build started on the first MN pod, leading to flood of API calls with many MN pods.
	mgr.GetClient().List(ctx, &networkv1.GKENetworkParamSetList{})

	return NewK8sClient(mgr.GetClient()), kubeletClient, dhcp.NewDHCPClient(), nil
}

// setupMultiNetworkingIPAMAllocators performs the following actions:
// 1. Initialises the IPAM allocators for the networks present on the node that is derived from the node annotations.
// 2. Allocates the IPs associated with the given endpoints inside the allocators created in step 1.
func setupMultiNetworkingIPAMAllocators(ctx context.Context, mnwIPAMMgr types.MultiNetworkIPAMManager, endpoints []*endpoint.Endpoint) error {
	if err := mnwIPAMMgr.UpdateMultiNetworkIPAMAllocators(node.GetAnnotations()); err != nil {
		return fmt.Errorf("failed to initialize multi-network allocators: %v", err)
	}
	if err := mnwIPAMMgr.PreAllocateIPsForRestoredMultiNICEndpoints(endpoints); err != nil {
		return fmt.Errorf("failed to pre-allocate IPs in multinetworking IPAM allocators for restored endpoints: %v", err)
	}
	return nil
}

// filteredCache returns a cache with a ListWatch that's restricted to the desired fields in order
// to reduce memory consumption.
func filteredCache(config *rest.Config, scheme *runtime.Scheme) cache.NewCacheFunc {
	resyncInterval := time.Minute * 10
	cacheOptions := cache.Options{
		Scheme:     scheme,
		SyncPeriod: &resyncInterval,
		ByObject: map[client.Object]cache.ByObject{
			&networkv1.Network{}: {},
			&corev1.Node{}: {
				Field: fields.SelectorFromSet(fields.Set{"metadata.name": nodeTypes.GetName()}),
			},
		},
	}
	return func(config *rest.Config, opts cache.Options) (cache.Cache, error) {
		return cache.New(config, cacheOptions)
	}
}

// PopulateNICInfoAnnotation populates the IP/PCI/name mapping of each PCI device on the node
// in a node annotation and patches the node.
func populateNICInfoAnnotation(ctx context.Context, k8sClient kubernetes.Interface) error {
	existingAnnotation, err := getNICInfoAnnotationFromNode()
	if err != nil {
		return fmt.Errorf("failed to get nic-info annotation from node: %v", err)
	}
	if existingAnnotation != nil {
		log.Infof("Skipping populating %v, annotation %v already exists", networkv1.NICInfoAnnotationKey, *existingAnnotation)
		return nil
	}

	// Enumerates all devices under /sys/class/net, ignoring 'lo' and non-PCI devices
	nics, err := nic.FindPCINICs()
	if err != nil {
		return err
	}
	numNICs := len(nics)
	if numNICs == 0 {
		return fmt.Errorf("no PCI NIC detected")
	}

	refs := make(networkv1.NICInfoAnnotation, numNICs)

	timeoutCtx, cancel := context.WithTimeout(ctx, timeoutWaitForIP)
	defer cancel()

	errs, _ := errgroup.WithContext(ctx)
	for i, nic := range nics {
		devName := nic.Name
		log.Infof("Found NIC %v", devName)

		link, err := safenetlink.LinkByName(devName)
		if err != nil {
			return fmt.Errorf("failed to find link by name %v: %v", devName, err)
		}
		idx := i
		// Use errgroup to bail on first non-recoverable error and kill all goroutines in the group.
		errs.Go(func() error {
			ip, err := waitForIP(timeoutCtx, link, netlink.FAMILY_V4, backoff.Exponential{})
			if err != nil {
				return err
			}
			refs[idx] = networkv1.NICInfoRef{BirthIP: ip, PCIAddress: *nics[idx].PCIAddress, BirthName: devName}
			return nil
		})
	}
	err = errs.Wait()
	if err != nil {
		return err
	}

	patch, err := getPatchForNICInfoAnnotation(&refs)
	if err != nil {
		return fmt.Errorf("failed to get nic-info patch: %v", err)
	}
	if _, err := k8sClient.CoreV1().Nodes().Patch(ctx, nodeTypes.GetName(), k8sTypes.StrategicMergePatchType, patch, metav1.PatchOptions{}); err != nil {
		return fmt.Errorf("unable to apply patch for %v annotation: %v", networkv1.NICInfoAnnotationKey, err)
	}
	log.Infof("Successfully applied %v annotation: %v", networkv1.NICInfoAnnotationKey, refs)
	return nil
}

func waitForIP(ctx context.Context, link netlink.Link, family int, backoff backoff.Exponential) (string, error) {
	for {
		// This is only used in non-dualstack GKE where we would only have one v4 CIDR per node NIC.
		// TODO(cuiwl): to support dualstack, we need to populate the address that north-interface
		// will expose.
		addrs, err := safenetlink.AddrList(link, netlink.FAMILY_V4)
		if err != nil {
			return "", fmt.Errorf("failed to get IP address for device %v: %v", link.Attrs().Name, err)
		}

		if len(addrs) > 0 {
			// Per the GKE MN API, there will be one and only one internal IPv4 address for each NIC.
			return addrs[0].IPNet.IP.String(), nil
		}

		err = backoff.Wait(ctx)
		if err != nil {
			return "", fmt.Errorf("timeout waiting for IP address for device %v to become available: %v", link.Attrs().Name, err)
		}
	}
}

func getPatchForNICInfoAnnotation(refs *networkv1.NICInfoAnnotation) ([]byte, error) {
	val, err := json.Marshal(refs)
	if err != nil {
		return nil, err
	}
	annotation := map[string]string{networkv1.NICInfoAnnotationKey: string(val)}
	raw, err := json.Marshal(annotation)
	if err != nil {
		return nil, err
	}
	return []byte(fmt.Sprintf(`{"metadata":{"annotations":%s}}`, raw)), nil
}

func getNICInfoAnnotationFromNode() (*networkv1.NICInfoAnnotation, error) {
	annotation, exists := node.GetAnnotations()[networkv1.NICInfoAnnotationKey]
	if !exists {
		log.Infof("no %v annotation: %v", networkv1.NICInfoAnnotationKey, node.GetAnnotations())
		return nil, nil
	}
	result, err := networkv1.ParseNICInfoAnnotation(annotation)
	if err != nil {
		return nil, err
	}
	return &result, nil
}
