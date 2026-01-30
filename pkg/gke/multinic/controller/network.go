package controller

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"reflect"

	networkv1 "github.com/GoogleCloudPlatform/gke-networking-api/apis/network/v1"
	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
	"github.com/cilium/cilium/pkg/datapath/loader"
	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/gke/multinic/multinicconfig"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/time"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"go.uber.org/multierr"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/workqueue"

	anutils "gke-internal.googlesource.com/anthos-networking/apis/v2/utils"
)

const (
	listNetworkTimeout = time.Second * 5
	// Directory to store all object files for multinic parent devices.
	multinicObjDir      = "/var/run/cilium/state/multinic"
	baseControllerDelay = 5 * time.Second
	maxControllerDelay  = 20 * time.Minute
)

var (
	logger = logging.DefaultLogger.WithField(logfields.LogSubsys, "gke-multinic-network-controller")
)

func (r *NetworkReconciler) reconcile(ctx context.Context, nwName string) (rerr error) {
	r.Log = logger.WithField("namespacedName", nwName)

	r.MetricsTrigger.Trigger()

	r.Log.Infof("Reconciling network %s", nwName)
	oldNode, err := r.LocalNode(ctx)
	if err != nil {
		return err
	}
	desiredNode := oldNode.DeepCopy()

	defer func() {
		err := r.patchNodeAnnotations(ctx, oldNode, desiredNode)
		rerr = multierr.Append(rerr, err)
	}()
	if multinicconfig.GlobalConfig.PopulateGCENICInfo {
		if err := r.handleHighPerfNetworks(ctx, desiredNode, oldNode); err != nil {
			return err
		}
	}
	nwStore, err := r.Networks.Store(ctx)
	if err != nil {
		return fmt.Errorf("failed to fetch networks store: %v", err)
	}
	network, exists, err := nwStore.GetByKey(resource.Key{Name: nwName})
	if err != nil {
		return fmt.Errorf("failed to fetch network %s: from store %v", nwName, err)
	}
	if !exists {
		r.Log.Info("Network not found. Ignoring because it was probably deleted.")
		// If Network IsNotFound, remove it from status
		if err := deleteFromNetworkStatus(ctx, desiredNode, nwName, "", "", r.Log); err != nil {
			r.Log.WithError(err).Errorf("Failed to update node network status annotation")
			return err
		}
		return nil
	}
	if !network.ObjectMeta.DeletionTimestamp.IsZero() {
		return r.reconcileNetworkDelete(ctx, desiredNode, network)
	}
	return r.reconcileNetwork(ctx, desiredNode, network)
}

// loadEBPFOnParent loads datapath ebpf programs on the parent interface.
func (r *NetworkReconciler) loadEBPFOnParent(ctx context.Context, network *networkv1.Network, node *slim_corev1.Node) error {
	if r.EndpointManager == nil {
		r.Log.Info("EndpointManager is nil. Please make sure the reconciler is initialized successfully")
		return nil
	}
	if networkv1.IsDefaultNetwork(network.Name) {
		return nil
	}
	devToLoad, _, err := anutils.InterfaceInfo(network, node.GetAnnotations())
	if err != nil {
		r.Log.Infof("errored generating interface name for network %s: %s", network.Name, err)
		return nil
	}

	hostEP, err := r.createHostEndpointIfNeeded(network.Name, devToLoad)
	if err != nil {
		return err
	}

	scopedLog := r.Log.WithFields(logrus.Fields{
		"network":           network.Name,
		logfields.Interface: devToLoad,
	})

	if r.isCiliumManaged(devToLoad) {
		scopedLog.Info("Skipping datapath loading for cilium-managed device")
		return nil
	}

	scopedLog.Info("Loading ebpf for network")
	// This returns nil if path already exists.
	objDir := path.Join(multinicObjDir, devToLoad)
	if err := os.MkdirAll(objDir, os.ModePerm); err != nil {
		return fmt.Errorf("failed to create multinic object dir: %v", err)
	}

	epInfo, err := hostEP.GetEpInfoCacheForCurrentDir()
	if err != nil {
		return fmt.Errorf("failed to get endpoint cache: %v", err)
	}
	if err := r.Loader.ReloadParentDevDatapath(ctx, devToLoad, epInfo); err != nil {
		return fmt.Errorf("datapath reload failed for device %q: %v", devToLoad, err)
	}

	scopedLog.Info("Datapath ebpf loaded successfully")
	return nil
}

// createHostEndpointIfNeeded returns the host endpoint associated with
// the network. If host endpoint does not exist for a network, then it is
// created.
func (r *NetworkReconciler) createHostEndpointIfNeeded(networkName, devToLoad string) (*endpoint.Endpoint, error) {
	// Wait for default host endpoint to come up before ensuring multi
	// nic host endpoint.
	hostEP := r.EndpointManager.GetHostEndpoint()
	if hostEP == nil {
		return nil, fmt.Errorf("host endpoint not found")
	}

	multiNICHostEP, err := r.HostEndpointManager.EnsureMultiNICHostEndpoint(r.RestoredHostEPs, networkName, devToLoad)
	if err != nil {
		return nil, fmt.Errorf("ensure multi nic host endpoint for network %s (parent-device %s): %w", networkName, devToLoad, err)
	}
	if multiNICHostEP != nil {
		return multiNICHostEP, nil
	}
	return hostEP, nil
}

// Delete the multi-NIC host endpoint and update RestoredHostEPs.
func (r *NetworkReconciler) deleteMultiNICHostEndpoint(network, devToUnload string) error {
	// Delete multinic host endpoint if exist.
	if err := r.HostEndpointManager.DeleteMultiNICHostEndpoint(network, devToUnload); err != nil {
		return err
	}
	// Remove the endpoint from RestoredHostEPs.
	updatedHostEPs := []*endpoint.Endpoint{}
	for _, ep := range r.RestoredHostEPs {
		if ep.GetNodeNetworkName() != network {
			updatedHostEPs = append(updatedHostEPs, ep)
		}
	}
	r.RestoredHostEPs = updatedHostEPs
	return nil
}

func (r *NetworkReconciler) unloadEBPFOnParent(ctx context.Context, network *networkv1.Network, node *slim_corev1.Node) error {
	devToUnload, _, err := anutils.InterfaceInfo(network, node.GetAnnotations())
	if err != nil {
		r.Log.Infof("errored generating interface name for network %s: %s", network.Name, err)
		return nil
	}

	scopedLog := r.Log.WithField(logfields.Interface, devToUnload)
	if r.isCiliumManaged(devToUnload) {
		scopedLog.Info("The parent interface is already a cilium-managed device. No need to reconcile")
		return nil
	}

	scopedLog.Info("Unloading ebpf")
	if err := loader.UnloadParentDevDatapath(ctx, devToUnload); err != nil {
		return err
	}

	if err := r.deleteMultiNICHostEndpoint(network.Name, devToUnload); err != nil {
		return fmt.Errorf("failed to delete multi nic host endpoint: %v", err)
	}

	if err := os.RemoveAll(path.Join(multinicObjDir, devToUnload)); err != nil {
		return fmt.Errorf("failed to remove multinic object dir: %v", err)
	}

	scopedLog.Info("Datapath ebpf unloaded successfully")
	return nil
}

func (r *NetworkReconciler) patchNodeAnnotations(ctx context.Context, oldNode, node *slim_corev1.Node) error {
	var oldVal, newVal string
	if node.Annotations != nil {
		newVal = node.Annotations[networkv1.NodeNetworkAnnotationKey]
	}
	if oldNode.Annotations != nil {
		oldVal = oldNode.Annotations[networkv1.NodeNetworkAnnotationKey]
	}
	if oldVal != newVal {
		r.Log.Infof("Patching %s annotation (old vs new): %s vs %s", networkv1.NodeNetworkAnnotationKey, oldVal, newVal)
		annotation := map[string]string{networkv1.NodeNetworkAnnotationKey: node.Annotations[networkv1.NodeNetworkAnnotationKey]}
		raw, err := json.Marshal(annotation)
		if err != nil {
			return fmt.Errorf("failed to build patch bytes for multi-networking: %w", err)
		}
		patch := []byte(fmt.Sprintf(`{"metadata":{"annotations":%s}}`, raw))
		if _, err := r.Clientset.CoreV1().Nodes().Patch(ctx, node.Name, types.StrategicMergePatchType, patch, metav1.PatchOptions{}); err != nil {
			return fmt.Errorf("failed to patch k8s node %q: %v", node.Name, err)
		}
	}
	return nil
}

func (r *NetworkReconciler) reconcileNetwork(ctx context.Context, node *slim_corev1.Node, network *networkv1.Network) (rerr error) {
	defer func() {
		if rerr == nil {
			r.Log.Info("Reconciled successfully")
		}
	}()
	if network.Spec.Type == networkv1.DeviceNetworkType {
		return nil
	}

	var err error
	var intfName string
	if !networkv1.IsDefaultNetwork(network.Name) {
		intfName, _, err = anutils.InterfaceInfo(network, node.GetAnnotations())
		if err != nil {
			// Log error and stop processing this event (no requeue), as this is
			// mostly due to misconfiguration in the network CR object and is unlikely
			// to reconcile. If missing north-interface annotation, new event will be
			// trigger on that annotation update (used by GKE).
			r.Log.Errorf("unable to discover interface name for network %s: %v", network.Name, err)
			return nil
		}
		if err := ensureInterface(network, intfName, r.Log); err != nil {
			return err
		}
	}

	if err := r.loadEBPFOnParent(ctx, network, node); err != nil {
		return err
	}
	// Obtain ip/subnet for node network
	ipv4, ipv6, err := r.obtainSubnet(network, node)
	if err != nil {
		r.Log.WithError(err).Error("Unable to read interface for subnets")
	}
	if err := addToNodeNetworkStatus(ctx, node, network.Name, ipv4, ipv6, r.Log); err != nil {
		return err
	}
	if err := r.updateMultiNetworkIPAM(ctx, network); err != nil {
		return err
	}
	if err := r.IPAMMgr.ReserveGatewayIP(network); err != nil {
		return err
	}
	if r.Config.EnableHostDeviceRoutingReconciliation {
		if err := r.updateHostDeviceRouting(ctx); err != nil {
			r.Log.WithError(err).Error("Failed to update host device routing map entries")
			return err
		}
	}
	r.Log.Info("Reconciled successfully")
	return nil
}

func (r *NetworkReconciler) reconcileNetworkDelete(ctx context.Context, node *slim_corev1.Node, network *networkv1.Network) (rerr error) {
	if network.Spec.Type == networkv1.DeviceNetworkType {
		return nil
	}
	inUseAnn := network.Annotations[networkv1.NetworkInUseAnnotationKey]
	if inUseAnn == networkv1.NetworkInUseAnnotationValTrue {
		r.Log.Infof("Network %q is still in use, exit reconciliation", network.Name)
		return nil
	}
	if err := r.unloadEBPFOnParent(ctx, network, node); err != nil {
		r.Log.WithError(err).Error("Unable to unload ebpf on parent interface")
		return err
	}
	if err := deleteVlanID(network, node, r.Log); err != nil {
		r.Log.WithError(err).Errorf("Unable to delete tagged interface")
		return err
	}
	if r.Config.EnableHostDeviceRoutingReconciliation {
		if err := r.updateHostDeviceRouting(ctx); err != nil {
			r.Log.WithError(err).Error("Failed to update host device routing map entries")
			return err
		}
	}
	if err := deleteFromNetworkStatus(ctx, node, network.Name, "", "", r.Log); err != nil {
		r.Log.WithError(err).Errorf("Failed to update node network status annotation")
		return err
	}

	r.networkErrorsLock.Lock()
	delete(r.networkErrors, network.Name)
	r.networkErrorsLock.Unlock()

	r.Log.Info("Reconciled on networkDelete successfully")
	return nil
}

func (r *NetworkReconciler) obtainSubnet(network *networkv1.Network, node *slim_corev1.Node) (string, string, error) {
	if networkv1.IsDefaultNetwork(network.Name) {
		return "", "", nil
	}
	intfName, _, err := anutils.InterfaceInfo(network, node.GetAnnotations())
	if err != nil {
		// Log error but return nil here as this is mostly due to misconfiguration
		// in the network CR object and is unlikely to reconcile.
		r.Log.Errorf("obtainSubnet: Errored generating interface name for network %s: %v", network.Name, err)
		return "", "", nil
	}
	link, err := safenetlink.LinkByName(intfName)
	if err != nil {
		return "", "", fmt.Errorf("failed to find parent interface %s: %q", intfName, err)
	}
	addrs, err := safenetlink.AddrList(link, netlink.FAMILY_V4)
	if err != nil {
		return "", "", fmt.Errorf("failed to list IPv4 addresses on interface")
	}
	bestIPv4Net := bestAddrMatch(addrs)

	addrs, err = safenetlink.AddrList(link, netlink.FAMILY_V6)
	if err != nil {
		return "", "", fmt.Errorf("failed to list IPv6 addresses on interface")
	}
	bestIPv6Net := bestAddrMatch(addrs)

	var ipv4, ipv6 string
	if bestIPv4Net != nil {
		ipv4 = bestIPv4Net.String()
	}
	if bestIPv6Net != nil {
		ipv6 = bestIPv6Net.String()
	}

	return ipv4, ipv6, nil
}

func (r *NetworkReconciler) isCiliumManaged(dev string) bool {
	// Multi-NIC host devices are managed by this controller.
	if node.IsMultiNICHostDevice(dev) {
		return false
	}
	selectedDevices, _ := tables.SelectedDevices(r.Devices, r.DB.ReadTxn())
	for _, d := range selectedDevices {
		if d.Name == dev {
			return true
		}
	}
	return false
}

func (r *NetworkReconciler) Run(ctx context.Context, networkChan <-chan resource.Event[*networkv1.Network], localNodeChan <-chan resource.Event[*slim_corev1.Node]) {
	r.Log.Info("Starting network controller")
	r.workqueue = workqueue.NewRateLimitingQueue(workqueue.NewItemExponentialFailureRateLimiter(baseControllerDelay, maxControllerDelay))
	r.networkErrors = make(map[string]int)

	go r.runWorker(ctx)

	for {
		select {
		case <-ctx.Done():
			r.Log.Info("context is done, shutting down network controller")
			r.workqueue.ShutDown()
			return
		case event, ok := <-networkChan:
			if !ok {
				return
			}
			r.processNetworkEvent(ctx, event)
		case event, ok := <-localNodeChan:
			if !ok {
				return
			}
			r.processNodeEvent(ctx, event)
		}
	}
}

func (r *NetworkReconciler) runWorker(ctx context.Context) {
	for r.processNextWorkItem(ctx) {
	}
}

func (r *NetworkReconciler) processNextWorkItem(ctx context.Context) bool {
	obj, shutdown := r.workqueue.Get()
	if shutdown {
		return false
	}
	defer r.workqueue.Done(obj)

	err := r.syncHandler(ctx, obj.(string))
	if err == nil {
		r.workqueue.Forget(obj)
	} else {
		if r.Config.NetworkReconcilerRetryLimit > 0 && r.workqueue.NumRequeues(obj) >= r.Config.NetworkReconcilerRetryLimit {
			r.Log.WithError(err).Errorf("error reconciling network %s after %d retries, giving up", obj.(string), r.Config.NetworkReconcilerRetryLimit)
			r.workqueue.Forget(obj)
		} else {
			r.Log.WithError(err).Errorf("error reconciling network %s, requeueing", obj.(string))
			r.workqueue.AddRateLimited(obj)
		}
	}
	return true
}

func (r *NetworkReconciler) syncHandler(ctx context.Context, nwName string) error {
	r.lastNetworksCacheLock.Lock()
	if r.lastNetworksCache == nil {
		r.lastNetworksCache = make(map[string]*networkv1.Network)
	}
	r.lastNetworksCacheLock.Unlock()

	err := r.reconcile(ctx, nwName)
	if err != nil {
		return err
	}
	// update local copy of current network upon successfully reconciliation
	nwStore, err := r.Networks.Store(ctx)
	if err != nil {
		return fmt.Errorf("failed to fetch networks store: %v", err)
	}
	nw, exists, err := nwStore.GetByKey(resource.Key{Name: nwName})
	if err != nil {
		return fmt.Errorf("failed to fetch network %s: from store %v", nwName, err)
	}

	r.lastNetworksCacheLock.Lock()
	defer r.lastNetworksCacheLock.Unlock()
	if !exists {
		delete(r.lastNetworksCache, nwName)
	} else {
		r.lastNetworksCache[nwName] = nw.DeepCopy()
	}
	return nil
}

func (r *NetworkReconciler) processNetworkEvent(ctx context.Context, event resource.Event[*networkv1.Network]) {
	if (event.Kind != resource.Upsert && event.Kind != resource.Delete) || event.Object == nil {
		event.Done(nil)
		return
	}
	nw := event.Object

	r.lastNetworksCacheLock.Lock()
	defer r.lastNetworksCacheLock.Unlock()
	if r.lastNetworksCache == nil {
		r.lastNetworksCache = make(map[string]*networkv1.Network)
	}
	oldNw, ok := r.lastNetworksCache[nw.Name]
	if ok && !networkNeedsReconcile(oldNw, nw) {
		r.lastNetworksCache[nw.Name] = nw.DeepCopy()
		r.Log.Infof("Received %s event for network %s, skipping reconciliation as there are no differences from old copy", event.Kind, nw.Name)
		event.Done(nil)
		return
	}
	r.Log.Infof("Received %s event for network: %s", event.Kind, nw.Name)
	r.networkErrorsLock.Lock()
	delete(r.networkErrors, nw.Name)
	r.networkErrorsLock.Unlock()
	r.workqueue.Add(nw.Name)
	event.Done(nil)
}

func networkNeedsReconcile(oldNet, newNet *networkv1.Network) bool {
	if !reflect.DeepEqual(oldNet.Spec, newNet.Spec) {
		return true
	}
	if !reflect.DeepEqual(oldNet.Status, newNet.Status) {
		return true
	}
	if !reflect.DeepEqual(oldNet.Finalizers, newNet.Finalizers) {
		return true
	}
	if !reflect.DeepEqual(oldNet.DeletionTimestamp, newNet.DeletionTimestamp) {
		return true
	}
	return false
}

func (r *NetworkReconciler) processNodeEvent(ctx context.Context, event resource.Event[*slim_corev1.Node]) {
	if event.Kind != resource.Upsert || event.Object == nil {
		event.Done(nil)
		return
	}
	r.Log.Infof("Received %s event for node: %s", event.Kind, event.Object.Name)

	// For every node event after the first one, the received object in the event will be compared to the existing local node within the reconciler.
	// This helps us to compare old and new versions of the object and reconcile only when there are any differences.
	if err := r.handleNodeEvent(ctx, event); err != nil {
		r.Log.Errorf("error while handling node event: %v", err)
		event.Done(err)
	} else {
		event.Done(nil)
	}
}

func (r *NetworkReconciler) handleNodeEvent(ctx context.Context, event resource.Event[*slim_corev1.Node]) error {
	var err error
	nodeFromEvent := event.Object
	if r.lastNode != nil && !nodeAnnotationsUpdated(r.lastNode, nodeFromEvent) {
		r.Log.Infof("No annotations updated, ignoring node event. existing networks annotations: %s", nodeFromEvent.Annotations[networkv1.MultiNetworkAnnotationKey])
		return nil
	}
	r.Log.Infof("Node annotations changed from recent event, proceeding with networks reconciliation")
	// Parse the annotations on the node and extract the networks to reconcile on.
	nws := mapNodeToNetwork(ctx, nodeFromEvent)
	var rerrs []error
	for _, nw := range nws {
		if err := r.reconcile(ctx, nw); err != nil {
			rerrs = append(rerrs, err)
		}
	}
	if len(rerrs) > 0 {
		err = fmt.Errorf("error while reconciling one or more networks on node: %s", r.NodeName)
	} else {
		// update local node copy with node from latest event
		r.lastNode = nodeFromEvent.DeepCopy()
	}
	return err
}

func (r *NetworkReconciler) LocalNode(ctx context.Context) (*slim_corev1.Node, error) {
	nodeStore, err := r.LocalNodeResource.Store(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch local node store: %v", err)
	}
	localNode, exists, err := nodeStore.GetByKey(resource.Key{Name: r.NodeName})
	if err != nil {
		return nil, fmt.Errorf("failed to fetch local node %s: %v", r.NodeName, err)
	}
	if !exists {
		return nil, fmt.Errorf("local node %s not found", r.NodeName)
	}
	return localNode, nil
}
