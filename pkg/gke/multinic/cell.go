package multinic

import (
	"context"
	"errors"
	"fmt"
	"os"

	"encoding/json"

	networkv1 "github.com/GoogleCloudPlatform/gke-networking-api/apis/network/v1"
	agentK8s "github.com/cilium/cilium/daemon/k8s"
	"github.com/cilium/cilium/pkg/backoff"
	linuxdatapath "github.com/cilium/cilium/pkg/datapath/linux"
	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
	"github.com/cilium/cilium/pkg/datapath/tables"
	datapath "github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/gke/multinic/controller"
	"github.com/cilium/cilium/pkg/gke/multinic/multinicconfig"
	"github.com/cilium/cilium/pkg/gke/multinic/nic"
	"github.com/cilium/cilium/pkg/gke/multinic/types"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/node"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/promise"
	"github.com/cilium/cilium/pkg/time"
	"github.com/cilium/cilium/pkg/trigger"
	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"
	"github.com/vishvananda/netlink"
	"golang.org/x/sync/errgroup"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sTypes "k8s.io/apimachinery/pkg/types"
)

const (
	minTriggerInternal = time.Second * 5
	// Directory to store all object files for multinic parent devices.
	multinicObjDir   = "/var/run/cilium/state/multinic"
	timeoutWaitForIP = 5 * time.Minute
)

var (
	log = logging.DefaultLogger.WithField(logfields.LogSubsys, "multinic")
)

var Cell = cell.Module(
	"google-multinetworking",
	"Google Multinetworking",

	cell.Invoke(initMultinetworking),
)

type Params struct {
	cell.In

	Lifecycle                cell.Lifecycle
	Config                   multinicconfig.Config
	IPAMMgrPromise           promise.Promise[types.MultiNetworkIPAMManager]
	HighPerfDeviceMgrPromise promise.Promise[types.DatapathReloader]
	HostEPMgrPromise         promise.Promise[types.HostEndpointManager]
	EmPromise                promise.Promise[endpointmanager.EndpointManager]
	// Write-only clients required by multinetwork reconciler to update
	// nodes
	K8sClient k8sClient.Clientset
	// Handle to the network API resources
	Networks            resource.Resource[*networkv1.Network]
	GKENetworkParamSets resource.Resource[*networkv1.GKENetworkParamSet]
	NetworkInterfaces   resource.Resource[*networkv1.NetworkInterface]
	// Handle to local node object required by multinic reconciler
	LocalNodeResource   agentK8s.LocalNodeResource
	DB                  *statedb.DB
	DeviceTable         statedb.Table[*tables.Device]
	GoogleDeviceManager *linuxdatapath.GoogleDeviceManager `optional:"true"`
	Datapath            datapath.Datapath
}

func initMultinetworking(p Params) error {
	if !p.Config.EnableGoogleMultiNIC {
		return nil
	}
	if p.GoogleDeviceManager == nil {
		return errors.New("GoogleDeviceManager must be provided")
	}
	multinicconfig.GlobalConfig = p.Config
	if !p.K8sClient.IsEnabled() {
		return nil
	}

	ctrlCtx, cancel := context.WithCancel(context.Background())
	p.Lifecycle.Append(cell.Hook{
		OnStart: func(ctx cell.HookContext) error {
			endpointManager, err := p.EmPromise.Await(ctx)
			if err != nil {
				return err
			}
			ipamMgr, err := p.IPAMMgrPromise.Await(ctx)
			if err != nil {
				return err
			}
			hpDevMgr, err := p.HighPerfDeviceMgrPromise.Await(ctx)
			if err != nil {
				return err
			}
			hostEpMgr, err := p.HostEPMgrPromise.Await(ctx)
			if err != nil {
				return err
			}
			if err := os.MkdirAll(multinicObjDir, os.ModePerm); err != nil {
				return err
			}

			// Filter host endpoints.
			var hostEPs []*endpoint.Endpoint
			for _, ep := range endpointManager.GetEndpoints() {
				if ep.IsHost() {
					hostEPs = append(hostEPs, ep)
				}
			}
			r := &controller.NetworkReconciler{
				Clientset:           p.K8sClient,
				Networks:            p.Networks,
				NodeName:            nodeTypes.GetName(),
				EndpointManager:     endpointManager,
				RestoredHostEPs:     hostEPs,
				IPAMMgr:             ipamMgr,
				DeviceMgr:           hpDevMgr,
				HostEndpointManager: hostEpMgr,
				DB:                  p.DB,
				Devices:             p.DeviceTable,
				Log:                 log,
				LocalNodeResource:   p.LocalNodeResource,
				GoogleDeviceManager: p.GoogleDeviceManager,
				Loader:              p.Datapath.Loader(),
				Config:              p.Config,
			}

			if err := r.SetupMultiNetworkingIPAMAllocators(r.IPAMMgr, r.EndpointManager.GetEndpoints()); err != nil {
				return fmt.Errorf("failed to initialize multi-network allocators: %v", err)
			}
			// Populates nic-info node annotation
			if p.Config.PopulateGCENICInfo {
				nicInfoAnnotation, existing, err := buildNICInfoAnnotation(ctx)
				if err != nil {
					return fmt.Errorf("unable to build nic annotations, high-perf networks will not work: %v", err)
				}
				if !existing {
					patch, err := getPatchForNICInfoAnnotation(nicInfoAnnotation)
					if err != nil {
						return fmt.Errorf("failed to get nic-info patch: %v", err)
					}
					if _, err := p.K8sClient.CoreV1().Nodes().Patch(ctx, nodeTypes.GetName(), k8sTypes.StrategicMergePatchType, patch, metav1.PatchOptions{}); err != nil {
						return fmt.Errorf("unable to apply patch for %v annotation: %v", networkv1.NICInfoAnnotationKey, err)
					}
				}
				if err := r.RestoreDevices(ctx, nicInfoAnnotation); err != nil {
					return fmt.Errorf("unable to reconcile high-perf network state: %v", err)
				}
			}

			t, err := trigger.NewTrigger(trigger.Parameters{
				Name:        "multi-network-endpoint-metrics",
				MinInterval: minTriggerInternal,
				TriggerFunc: r.UpdateMultiNetMetrics,
			})
			if err != nil {
				return fmt.Errorf("unable to initialize endpoint trigger function: %v", err)
			}
			r.MetricsTrigger = t

			// Optimization for scalablity.
			// The dumb list call triggers the cache build for GKENetworkParamSet.
			// Without this, the cache build started on the first MN pod, leading to flood of API calls with many MN pods.
			if p.GKENetworkParamSets != nil {
				gnpStore, err := p.GKENetworkParamSets.Store(ctx)
				if err != nil {
					return fmt.Errorf("failed to fetch gkenetworkparamset store during initialisation: %v", err)
				}
				gnpStore.List()
			}
			// process network and node events -- non-blocking
			go r.Run(ctrlCtx, p.Networks.Events(ctrlCtx), p.LocalNodeResource.Events(ctrlCtx))

			r.Log.Info("successfully started google multinetworking controller")
			return nil
		},
		OnStop: func(hc cell.HookContext) error {
			cancel()
			return nil
		},
	})

	return nil
}

// buildNICInfoAnnotation populates the IP/PCI/name mapping of each PCI device on the node
// in a node annotation.
func buildNICInfoAnnotation(ctx context.Context) (*networkv1.NICInfoAnnotation, bool, error) {
	existingAnnotation, err := getNICInfoAnnotationFromNode()
	if err != nil {
		return nil, false, fmt.Errorf("failed to get nic-info annotation from node: %v", err)
	}
	if existingAnnotation != nil {
		log.Infof("Skipping populating %v, annotation %v already exists", networkv1.NICInfoAnnotationKey, *existingAnnotation)
		return existingAnnotation, true, nil
	}

	// Enumerates all devices under /sys/class/net, ignoring 'lo' and non-PCI devices
	nics, err := nic.FindPCINICs()
	if err != nil {
		return nil, false, fmt.Errorf("failed to find PCI NICs: %v", err)
	}
	numNICs := len(nics)
	if numNICs == 0 {
		return nil, false, fmt.Errorf("no PCI NIC detected")
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
			return nil, false, fmt.Errorf("failed to find link by name %v: %v", devName, err)
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
		return nil, false, err
	}
	return &refs, false, nil
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
