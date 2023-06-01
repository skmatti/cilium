package controller

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path"
	"sort"
	"time"

	"github.com/cilium/cilium/pkg/datapath/connector"
	"github.com/cilium/cilium/pkg/datapath/loader"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/gke/multinic/nic"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/metrics"
	ciliumNode "github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/trigger"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"go.uber.org/multierr"
	corev1 "k8s.io/api/core/v1"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	meta "k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/types"
	networkv1 "k8s.io/cloud-provider-gcp/crd/apis/network/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/source"

	"github.com/cilium/cilium/pkg/endpointmanager"
	anutils "gke-internal.googlesource.com/anthos-networking/apis/v2/utils"
)

const (
	listNetworkTimeout = time.Second * 5
	minTriggerInternal = time.Second * 5
)

var (
	logger = logging.DefaultLogger.WithField(logfields.LogSubsys, "gke-multinic-network-controller")
)

// NetworkReconciler reconciles network objects.
type NetworkReconciler struct {
	client.Client
	EndpointManager *endpointmanager.EndpointManager
	NodeName        string
	IPAMMgr         ipamManager
	DeviceMgr       deviceManager
	// invariant: at the end of every reconcile, the keys to this map are every nic listed in
	// nic-info.
	//
	// For every nic where controllerManaged[nic]=true, nic is in the host netns and
	// bpf is unloaded on the device, or the device doesn't exist in host netns (has been moved
	// into pod). The network corresponding to nic is in the network-status annotation
	//
	// For every nic where controllerManaged[nic]=false, the nic is in the hostns, bpf
	// is loaded on nic, and nic is in the cilium devices list.
	controllerManaged map[string]bool
	metricsTrigger    *trigger.Trigger
}

type ipamManager interface {
	UpdateMultiNetworkIPAMAllocators(annotations map[string]string) error
	ReserveGatewayIP(network *networkv1.Network) error
	AllocateIP(ip, owner string) error
}
type deviceManager interface {
	ReloadOnDeviceChange(devices []string)
}

const (
	// Directory to store all object files for multinic parent devices.
	multinicObjDir = "/var/run/cilium/state/multinic"
)

func (r *NetworkReconciler) EndpointCreated(ep *endpoint.Endpoint) {
	r.metricsTrigger.Trigger()
}

func (r *NetworkReconciler) EndpointDeleted(ep *endpoint.Endpoint, conf endpoint.DeleteConfig) {
	r.metricsTrigger.Trigger()
}

func (r *NetworkReconciler) updateMultiNetMetrics(reasons []string) {
	ctxTimeout, cancel := context.WithTimeout(context.TODO(), listNetworkTimeout)
	defer cancel()

	logger.Debug("Updating multi-network endpoint metrics")

	// Construct a map of network ID -> number of endpoints
	netEpCount := make(map[uint32]int)
	eps := r.EndpointManager.GetEndpoints()
	for _, ep := range eps {
		id := ep.DatapathConfiguration.NetworkID
		netEpCount[id] += 1
	}

	var networkList networkv1.NetworkList
	if err := r.List(ctxTimeout, &networkList); err != nil {
		logger.WithError(err).Warn("Failed to update multi-network endpoint metrics")
		return
	}
	// For each network, export the number of endpoints
	for _, network := range networkList.Items {
		id := connector.GenerateNetworkID(&network)
		netType := string(network.Spec.Type)
		epCount := netEpCount[id]
		metrics.MultiNetworkEndpoint.WithLabelValues(network.Name, netType).Set(float64(epCount))
	}
}

func (r *NetworkReconciler) Reconcile(ctx context.Context, req ctrl.Request) (_ ctrl.Result, rerr error) {
	if !option.Config.EnableGoogleMultiNIC {
		return ctrl.Result{}, nil
	}
	log := logger.WithField("namespacedName", req.NamespacedName)

	r.metricsTrigger.Trigger()

	log.Info("Reconciling")
	oldNode := &corev1.Node{}
	if err := r.Get(ctx, types.NamespacedName{Name: r.NodeName}, oldNode); err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to get k8s node %q: %v", r.NodeName, err)
	}
	// Reset annotations so we don't override anything outside of anetd's scope.
	node := oldNode.DeepCopy()
	node.Annotations = make(map[string]string)
	if oldNode.Annotations != nil {
		node.Annotations[networkv1.NodeNetworkAnnotationKey] = oldNode.Annotations[networkv1.NodeNetworkAnnotationKey]
		// TODO(b/269187538): Remove once DefaultNetworkName is deprecated.
		if len(node.Annotations[networkv1.NodeNetworkAnnotationKey]) == 0 {
			node.Annotations[networkv1.NodeNetworkAnnotationKey] = "[]"
		}
	}
	defer func() {
		err := r.patchNodeAnnotations(ctx, log, oldNode, node)
		rerr = multierr.Append(rerr, err)
	}()
	if option.Config.PopulateGCENICInfo {
		oldNetworkStatus, err := getNetworkStatusMap(node)
		add, remove, err := r.reconcileHighPerfNetworks(ctx, oldNetworkStatus, oldNode, log)
		if err != nil {
			log.WithError(err).Error("Failed to reconcile device-typed networks")
			return ctrl.Result{}, err
		}
		for _, a := range add {
			log.Debugf("adding %s to network-status annotation", a)
			if err := addNodeNetworkAnnotation(ctx, node, a, "", "", log); err != nil {
				log.WithError(err).Error("Failed to update node network status annotation")
				return ctrl.Result{}, err
			}
		}
		for _, a := range remove {
			log.Debugf("removing %s to network-status annotation", a)
			if err := deleteNodeNetworkAnnotation(ctx, node, a, "", "", log); err != nil {
				log.WithError(err).Error("Failed to update node network status annotation")
				return ctrl.Result{}, err
			}
		}
	}
	network := &networkv1.Network{}
	if err := r.Get(ctx, req.NamespacedName, network); err != nil {
		if k8sErrors.IsNotFound(err) {
			log.Info("Network not found. Ignoring because it was probably deleted.")
			return ctrl.Result{}, nil
		}
		log.WithError(err).Error("Unable to get network object")
		return ctrl.Result{}, err
	}
	if !network.ObjectMeta.DeletionTimestamp.IsZero() {
		return r.reconcileNetworkDelete(ctx, node, network, log)
	}

	return r.reconcileNetwork(ctx, node, network, log)
}

// SetupWithManager configures this controller in the manager.
func (r *NetworkReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if err := os.MkdirAll(multinicObjDir, os.ModePerm); err != nil {
		return err
	}
	t, err := trigger.NewTrigger(trigger.Parameters{
		Name:        "multi-network-endpoint-metrics",
		MinInterval: minTriggerInternal,
		TriggerFunc: r.updateMultiNetMetrics,
	})
	if err != nil {
		return fmt.Errorf("unable to initialize endpoint trigger function: %v", err)
	}
	r.metricsTrigger = t
	// Only subscribe to endpoint manager when manager is started
	mgr.Add(manager.RunnableFunc(func(context.Context) error {
		r.EndpointManager.Subscribe(r)
		return nil
	}))
	return ctrl.NewControllerManagedBy(mgr).
		For(&networkv1.Network{}).
		Watches(&source.Kind{Type: &corev1.Node{}},
			handler.EnqueueRequestsFromMapFunc(r.mapNodeToNetwork),
			builder.WithPredicates(
				predicate.Funcs{
					UpdateFunc: func(e event.UpdateEvent) bool {
						if e.ObjectOld.GetAnnotations()[networkv1.MultiNetworkAnnotationKey] != e.ObjectNew.GetAnnotations()[networkv1.MultiNetworkAnnotationKey] {
							return true
						}
						return false
					},
				})).
		Complete(r)
}

func setLinkName(link netlink.Link, name string) error {
	err := netlink.LinkSetDown(link)
	if err != nil {
		return fmt.Errorf("unable to turn device %s down, error: %v", link, err)
	}
	err = netlink.LinkSetName(link, name)
	if err != nil {
		return fmt.Errorf("unable to rename device %s to %s, err: %v", link, name, err)
	}
	err = netlink.LinkSetUp(link)
	if err != nil {
		return fmt.Errorf("unable to turn device %s up, err: %v", link, err)
	}
	return nil
}

// Init renames all devices found to their birthname and sets the anetd devices list. Does *not*
// update the annotations.
func (r *NetworkReconciler) RestoreDevices(ctx context.Context, node *corev1.Node, log *logrus.Entry) error {
	controllerMap := make(map[string]bool)
	links, err := netlink.LinkList()
	if err != nil {
		return fmt.Errorf("failed to list links: %v", err)
	}
	nicInfo, err := getNicInfo(node)
	if err != nil {
		return fmt.Errorf("failed to get nic-info: %v", err)
	}

	for _, val := range nicInfo {
		// we mark every device as owned by us, then unmark devices
		// that cilium will see in netns. This lets us mark devices
		// that in are in pods as owned by us. See end of loop below
		controllerMap[val.birthName] = true
	}
	// we take a copy of the list so we can make one atomic change
	ciliumDevicesList := make([]string, len(option.Config.GetDevices()))
	copy(ciliumDevicesList, option.Config.GetDevices())
	for _, link := range links {
		dev := link.Attrs().Name
		isVirt, err := nic.IsVirtual(dev)
		if err != nil {
			return err
		}
		if isVirt || dev == nic.LoopbackDevName {
			continue
		}
		needsRename, birthname, err := checkNeedsRename(dev, nicInfo, log)
		if err != nil {
			return err
		}
		if needsRename {
			if err := setLinkName(link, birthname); err != nil {
				return err
			}
			if idx := findInSlice(ciliumDevicesList, dev); idx != -1 {
				ciliumDevicesList[idx] = birthname
			}
			dev = birthname
		}
		// cilium will steal every device in root netns
		controllerMap[dev] = false
	}
	sort.Strings(ciliumDevicesList)
	option.Config.SetDevices(ciliumDevicesList)
	r.controllerManaged = controllerMap
	log.Infof("initialized map with current device state: %v", r.controllerManaged)

	return nil
}

func (r *NetworkReconciler) mapNodeToNetwork(obj client.Object) []ctrl.Request {
	node := obj.(*corev1.Node)
	log := ctrl.Log.WithValues("name", client.ObjectKeyFromObject(node))
	log.Info("mapNodeToNetwork")
	// The default pod-network is always expected to be present. Hence, we reconcile on the default pod-network
	// whenever multi-network annotation changes. Note that the default pod-network is not a part of multi-network
	// annotation. The reconcilation flow parses through the multi-network annotation and builds the allocators
	// accordingly.
	return []ctrl.Request{
		{
			// TODO(b/269187538): Remove request from the list once DefaultNetworkName is deprecated.
			NamespacedName: types.NamespacedName{Name: networkv1.DefaultNetworkName},
		},
		{
			NamespacedName: types.NamespacedName{Name: networkv1.DefaultPodNetworkName},
		},
	}
}

func isCiliumManaged(dev string) bool {
	for _, d := range option.Config.GetDevices() {
		if d == dev {
			return true
		}
	}
	return false
}

// loadEBPFOnParent loads datapath ebpf programs on the parent interface.
func (r *NetworkReconciler) loadEBPFOnParent(ctx context.Context, network *networkv1.Network, node *corev1.Node, log *logrus.Entry) error {
	if r.EndpointManager == nil {
		log.Info("EndpointManager is nil. Please make sure the reconciler is initialized successfully")
		return nil
	}
	if networkv1.IsDefaultNetwork(network.Name) {
		log.Infof("No need to load ebpf for default network: %v", network.Name)
		return nil
	}
	devToLoad, _, err := anutils.InterfaceInfo(network, node.GetAnnotations())
	if err != nil {
		log.Infof("errored generating interface name for network %s: %s", network.Name, err)
		return nil
	}

	scopedLog := log.WithField(logfields.Interface, devToLoad)
	if isCiliumManaged(devToLoad) {
		scopedLog.Info("The parent interface is already a cilium-managed device. No need to reconcile")
		return nil
	}

	scopedLog.WithField("network", network.Name).Infof("Loading ebpf for network")
	objDir := path.Join(multinicObjDir, devToLoad)
	if err := os.MkdirAll(objDir, os.ModePerm); err != nil {
		return fmt.Errorf("failed to create multinic object dir: %v", err)
	}

	hostEp := r.EndpointManager.GetHostEndpoint()
	if hostEp == nil {
		return errors.New("waiting for host endpoint to come up. Will retry.")
	}
	epInfo, err := hostEp.GetEpInfoCacheForCurrentDir()
	if err != nil {
		return fmt.Errorf("failed to get endpoint cache: %v", err)
	}
	if err := loader.ReloadParentDevDatapath(ctx, devToLoad, objDir, epInfo); err != nil {
		return fmt.Errorf("datapath reload failed for device %q: %v", devToLoad, err)
	}

	scopedLog.Info("Datapath ebpf loaded successfully")
	return nil
}

func (r *NetworkReconciler) unloadEBPFOnParent(ctx context.Context, network *networkv1.Network, node *corev1.Node, log *logrus.Entry) error {
	devToUnload, _, err := anutils.InterfaceInfo(network, node.GetAnnotations())
	if err != nil {
		log.Infof("errored generating interface name for network %s: %s", network.Name, err)
		return nil
	}

	scopedLog := log.WithField(logfields.Interface, devToUnload)
	if isCiliumManaged(devToUnload) {
		scopedLog.Info("The parent interface is already a cilium-managed device. No need to reconcile")
		return nil
	}

	scopedLog.Info("Unloading ebpf")
	if err := loader.UnloadParentDevDatapath(ctx, devToUnload); err != nil {
		return err
	}

	if err := os.RemoveAll(path.Join(multinicObjDir, devToUnload)); err != nil {
		return fmt.Errorf("failed to remove multinic object dir: %v", err)
	}

	scopedLog.Info("Datapath ebpf unloaded successfully")
	return nil
}

// ensureVlanID ensures that an interface named `parentIntName.vlanID` exists with
// the proper vlan ID
func ensureVlanID(vlanIntName string, vlanID int, parentLink netlink.Link, log *logrus.Entry) error {
	// check if tagged interface already exists
	link, err := netlink.LinkByName(vlanIntName)
	if err == nil {
		origVlan, ok := link.(*netlink.Vlan)
		if !ok {
			return fmt.Errorf("interface %s is not a vlan (%+v)", vlanIntName, origVlan)
		}

		if origVlan.VlanId != vlanID {
			return fmt.Errorf("existing interface %s has vlan id %d, expected %d", vlanIntName, origVlan.VlanId, vlanID)
		}
		if parentLink.Attrs().Index != origVlan.Attrs().ParentIndex {
			return fmt.Errorf("existing interface %s has parent interface %s, expected %s", vlanIntName, origVlan.Attrs().Name, parentLink.Attrs().Name)
		}
	} else {
		vlan := netlink.Vlan{
			LinkAttrs: netlink.LinkAttrs{
				ParentIndex: parentLink.Attrs().Index,
				Name:        vlanIntName,
			},
			VlanId: vlanID,
		}

		if err := netlink.LinkAdd(&vlan); err != nil {
			return fmt.Errorf("failed to create tagged interface %s : %q", vlanIntName, err)
		}

		link = &vlan
	}

	if err := netlink.LinkSetUp(link); err != nil {
		return fmt.Errorf("failed to bring up network vlan interface %q: %v", vlanIntName, err)
	}

	log.WithField("vlan", vlanIntName).Info("Ensured vlan interface")
	return nil
}

// getNetworkStatusMap returns a map of networks to the corresponding status on the node.
// The information is parsed from the node annotation.
func getNetworkStatusMap(node *corev1.Node) (map[string]networkv1.NodeNetworkStatus, error) {
	netStatusMap := make(map[string]networkv1.NodeNetworkStatus)
	annotation := node.Annotations[networkv1.NodeNetworkAnnotationKey]
	if len(annotation) == 0 {
		return netStatusMap, nil
	}
	netAnn, err := networkv1.ParseNodeNetworkAnnotation(annotation)
	if err != nil {
		return nil, err
	}
	for _, n := range netAnn {
		netStatusMap[n.Name] = n
	}
	return netStatusMap, nil
}

func marshalNodeNetworkAnnotation(statusMap map[string]networkv1.NodeNetworkStatus) (string, error) {
	ann := make(networkv1.NodeNetworkAnnotation, 0, len(statusMap))
	for _, net := range statusMap {
		ann = append(ann, net)
	}
	sort.Slice(ann, func(i, j int) bool {
		return ann[i].Name < ann[j].Name
	})
	return networkv1.MarshalNodeNetworkAnnotation(ann)
}

func updateNodeNetworkAnnotation(ctx context.Context, node *corev1.Node, networkName string, ipv4, ipv6 string, log *logrus.Entry, isAdd bool) error {
	log.WithFields(logrus.Fields{
		logfields.NodeName: node.Name,
		"network":          networkName,
	}).Info("Updating node network status annotation")
	netStatusMap, err := getNetworkStatusMap(node)
	if err != nil {
		return fmt.Errorf("failed to get network status map from node %q: %v", node.Name, err)
	}
	log.Infof("existing node network status annotation %+v", netStatusMap)

	oldNetAnnotation, exist := netStatusMap[networkName]
	if isAdd {
		if exist && oldNetAnnotation.IPv4Subnet == ipv4 && oldNetAnnotation.IPv6Subnet == ipv6 {
			log.Infof("network %q already exists on the node %q", networkName, node.Name)
			return nil
		}
		netStatusMap[networkName] = networkv1.NodeNetworkStatus{Name: networkName, IPv4Subnet: ipv4, IPv6Subnet: ipv6}
	} else {
		if !exist {
			log.Infof("network %q doesn't exist on the node %q", networkName, node.Name)
			return nil
		}
		delete(netStatusMap, networkName)
	}
	log.Infof("node network status annotation to update %+v", netStatusMap)
	netAnnotations, err := marshalNodeNetworkAnnotation(netStatusMap)
	if err != nil {
		return fmt.Errorf("failed to marshal node network annotation %v: %v", netStatusMap, err)
	}

	if node.Annotations == nil {
		node.Annotations = make(map[string]string)
	}
	node.Annotations[networkv1.NodeNetworkAnnotationKey] = netAnnotations
	log.Info("Updated node network status annotation")
	return nil
}

func addNodeNetworkAnnotation(ctx context.Context, node *corev1.Node, networkName string, ipv4, ipv6 string, log *logrus.Entry) error {
	return updateNodeNetworkAnnotation(ctx, node, networkName, ipv4, ipv6, log, true)
}

func deleteNodeNetworkAnnotation(ctx context.Context, node *corev1.Node, networkName string, ipv4, ipv6 string, log *logrus.Entry) error {
	return updateNodeNetworkAnnotation(ctx, node, networkName, ipv4, ipv6, log, false)
}

func (r *NetworkReconciler) patchNodeAnnotations(ctx context.Context, log *logrus.Entry, oldNode, node *corev1.Node) error {
	// Do not patch if node annotations are all contained in old Nodes
	// annotation.
	doPatch := false
	// If annotations the same length, check each annotation and ensure that
	// they match.
	if oldNode.Annotations != nil {
		for key, value := range node.Annotations {
			oldValue, ok := oldNode.Annotations[key]
			if oldValue != value || !ok {
				doPatch = true
				break
			}
		}
	} else {
		doPatch = true
	}

	if !doPatch {
		return nil
	}
	raw, err := json.Marshal(node.Annotations)
	if err != nil {
		return fmt.Errorf("failed to marshall node annotations for node %q: %v", node.Name, err)
	}

	patch := []byte(fmt.Sprintf(`{"metadata":{"annotations":%s}}`, raw))
	if err := r.Client.Status().Patch(ctx, node, client.RawPatch(types.StrategicMergePatchType, patch)); err != nil {
		return fmt.Errorf("failed to patch k8s node %q: %v", node.Name, err)
	}
	return nil
}

func (r *NetworkReconciler) updateMultiNetworkIPAM(ctx context.Context, network *networkv1.Network, log *logrus.Entry) error {
	if network.Spec.ExternalDHCP4 != nil && *network.Spec.ExternalDHCP4 {
		log.Info("external DHCP enabled for network, no need to update IPAM maps")
		return nil
	}
	node := &corev1.Node{}
	if err := r.Get(ctx, types.NamespacedName{Name: r.NodeName}, node); err != nil {
		return err
	}
	if err := r.IPAMMgr.UpdateMultiNetworkIPAMAllocators(node.Annotations); err != nil {
		return err
	}
	log.Info("multi-net IPAM map is updated successfully")
	return nil
}

func (r *NetworkReconciler) reconcileNetwork(ctx context.Context, node *corev1.Node, network *networkv1.Network, log *logrus.Entry) (_ ctrl.Result, rerr error) {
	if network.Spec.Type == networkv1.DeviceNetworkType {
		return ctrl.Result{}, nil
	}
	// Remove network from node if we fail along the way.
	if err := deleteNodeNetworkAnnotation(ctx, node, network.Name, "", "", log); err != nil {
		log.WithError(err).Error("Failed to update node network status annotation")
		return ctrl.Result{}, err
	}
	if err := ensureInterface(network, log); err != nil {
		log.WithError(err).Error("Unable to ensure network interface")
		return ctrl.Result{}, err
	}
	if err := r.loadEBPFOnParent(ctx, network, node, log); err != nil {
		log.WithError(err).Error("Unable to load ebpf on parent interface")
		return ctrl.Result{}, err
	}
	// Obtain ip/subnet for node network
	ipv4, ipv6, err := r.obtainSubnet(network, node, log)
	if err != nil {
		log.WithError(err).Error("Unable to read interface for subnets")
	}
	if err := addNodeNetworkAnnotation(ctx, node, network.Name, ipv4, ipv6, log); err != nil {
		log.WithError(err).Error("Failed to update node network status annotation")
		return ctrl.Result{}, err
	}
	if err := r.updateMultiNetworkIPAM(ctx, network, log); err != nil {
		log.WithError(err).Error("Failed to update node multi-network IPAM")
		return ctrl.Result{}, err
	}
	if err := r.IPAMMgr.ReserveGatewayIP(network); err != nil {
		log.WithError(err).Error("Failed to reserve gateway IP")
		return ctrl.Result{}, err
	}
	log.Info("Reconciled successfully")
	return ctrl.Result{}, nil
}

func checkNetworkAlive(network *networkv1.Network) bool {
	return meta.IsStatusConditionTrue(network.Status.Conditions, "Ready") && network.ObjectMeta.DeletionTimestamp.IsZero()
}

func (r *NetworkReconciler) reconcileNetworkDelete(ctx context.Context, node *corev1.Node, network *networkv1.Network, log *logrus.Entry) (_ ctrl.Result, rerr error) {
	if network.Spec.Type != networkv1.DeviceNetworkType {
		inUseAnn := network.Annotations[networkv1.NetworkInUseAnnotationKey]
		if inUseAnn == networkv1.NetworkInUseAnnotationValTrue {
			log.Infof("Network %q is still in use, exit reconciliation", network.Name)
			return ctrl.Result{}, nil
		}
		if err := r.unloadEBPFOnParent(ctx, network, node, log); err != nil {
			log.WithError(err).Error("Unable to unload ebpf on parent interface")
			return ctrl.Result{}, err
		}
		if err := deleteVlanID(network, log); err != nil {
			log.WithError(err).Errorf("Unable to delete tagged interface")
			return ctrl.Result{}, err
		}
		if err := updateNodeNetworkAnnotation(ctx, node, network.Name, "", "", log, false); err != nil {
			log.WithError(err).Errorf("Failed to update node network status annotation")
			return ctrl.Result{}, err
		}
	}
	log.Info("Reconciled on networkDelete successfully")
	return ctrl.Result{}, nil
}

// deleteVlanID deletes the specified vlan tag in the the Network CR if
// lifecycle is AnthosManaged
// TODO(b/283301614):
func deleteVlanID(network *networkv1.Network, log *logrus.Entry) error {
	if !hasVlanTag(network) {
		return nil
	}

	taggedIntName, _, err := anutils.InterfaceInfo(network, ciliumNode.GetAnnotations())
	if err != nil {
		log.Errorf("deleteVlanID: Errored generating interface name for network %s: %s", network.Name, err)
		return nil
	}

	link, err := netlink.LinkByName(taggedIntName)
	if err != nil {
		if _, ok := err.(netlink.LinkNotFoundError); ok {
			log.Infof("Link for host interface %s for network %s does not exist or was already deleted: %s", taggedIntName, network.Name, err)
			return nil
		}
		return fmt.Errorf("errored getting link for host interface %s for network %s: %w", taggedIntName, network.Name, err)
	}

	log.Infof("Deleting interface %s for network %s", taggedIntName, network.Name)
	err = netlink.LinkDel(link)
	if err != nil {
		return fmt.Errorf("failed to delete vlan %s for network %s: %w", taggedIntName, network.Name, err)
	}

	return nil
}

func hasVlanTag(network *networkv1.Network) bool {
	if network.Spec.L2NetworkConfig == nil || network.Spec.L2NetworkConfig.VlanID == nil {
		return false
	}

	if network.Spec.NetworkLifecycle != nil && *network.Spec.NetworkLifecycle == networkv1.UserManagedLifecycle {
		return false
	}
	return true

}

func ensureInterface(network *networkv1.Network, log *logrus.Entry) error {
	if networkv1.IsDefaultNetwork(network.Name) {
		return nil
	}
	intfName, _, err := anutils.InterfaceInfo(network, ciliumNode.GetAnnotations())
	if err != nil {
		// Log error but return nil here as this is mostly due to misconfiguration
		// in the network CR object and is unlikely to reconcile.
		log.Errorf("ensureInterface: Errored generating interface name for network %s: %v", network.Name, err)
		return nil
	}
	scopedLog := log.WithField(logfields.Interface, intfName)
	parentIntName := intfName
	if network.Spec.L2NetworkConfig != nil && network.Spec.L2NetworkConfig.VlanID != nil {
		parentIntName = *network.Spec.NodeInterfaceMatcher.InterfaceName
	}
	link, err := netlink.LinkByName(parentIntName)
	if err != nil {
		return fmt.Errorf("failed to find parent interface %s: %q", parentIntName, err)
	}
	if err := netlink.LinkSetUp(link); err != nil {
		return fmt.Errorf("failed to bring up network parent interface %q: %v", parentIntName, err)
	}
	scopedLog.WithField("parentInterface", parentIntName).Info("Ensured parent interface")

	if hasVlanTag(network) {
		if err := ensureVlanID(intfName, int(*network.Spec.L2NetworkConfig.VlanID), link, scopedLog); err != nil {
			return err
		}
	}

	return nil
}

// bestAddrMatch scans the given list of IP addresses and returns the one that
// "best" fits the match of what we consider the nodes IP address on the
// network. An IP that has the global attribute, along with the largest subnet
// range is considered the best match. We do this to filter out IPs such as ANG
// floating IPs which have a /32 cidr range and local IP addresses.
//
// e.g 10.0.0.1/28 > 10.0.0.2/30
func bestAddrMatch(addrs []netlink.Addr) *net.IPNet {
	var ipNet *net.IPNet
	for _, addr := range addrs {
		if netlink.Scope(addr.Scope) == netlink.SCOPE_UNIVERSE {
			if ipNet == nil {
				ipNet = addr.IPNet
				continue
			}

			// Check and replace if the cidr is larger to remove addresses added
			// to the interface by ANG and to get the largest subnet supported
			// by that network.
			ipNetPrefixSize, _ := ipNet.Mask.Size()
			addrPrefixSize, _ := addr.IPNet.Mask.Size()
			if ipNetPrefixSize > addrPrefixSize {
				ipNet = addr.IPNet
			}
		}
	}
	return ipNet
}

func (r *NetworkReconciler) obtainSubnet(network *networkv1.Network, node *corev1.Node, log *logrus.Entry) (string, string, error) {
	if networkv1.IsDefaultNetwork(network.Name) {
		return "", "", nil
	}
	intfName, _, err := anutils.InterfaceInfo(network, node.GetAnnotations())
	if err != nil {
		// Log error but return nil here as this is mostly due to misconfiguration
		// in the network CR object and is unlikely to reconcile.
		log.Errorf("obtainSubnet: Errored generating interface name for network %s: %v", network.Name, err)
		return "", "", nil
	}
	link, err := netlink.LinkByName(intfName)
	if err != nil {
		return "", "", fmt.Errorf("failed to find parent interface %s: %q", intfName, err)
	}
	addrs, err := netlink.AddrList(link, netlink.FAMILY_V4)
	if err != nil {
		return "", "", fmt.Errorf("failed to list IPv4 addresses on interface")
	}
	bestIPv4Net := bestAddrMatch(addrs)

	addrs, err = netlink.AddrList(link, netlink.FAMILY_V6)
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

type nicMapValue struct {
	pciAddress string
	birthName  string
}

// getNicInfo returns a map from ip to pciaddress, birth name.
func getNicInfo(node *corev1.Node) (map[string]nicMapValue, error) {
	nicAnnotationString, ok := node.GetAnnotations()[networkv1.NICInfoAnnotationKey]
	if !ok {
		return nil, fmt.Errorf("nic-info annotation does not exist, looking for annotation with key %s", networkv1.NICInfoAnnotationKey)
	}
	result := make(map[string]nicMapValue)
	if nicAnnotationString == "" {
		return nil, fmt.Errorf("nic-info annotation is empty")
	}
	nicAnnotation, err := networkv1.ParseNICInfoAnnotation(nicAnnotationString)
	if err != nil {
		return nil, fmt.Errorf("error parsing nic-info annotation: %v", err)
	}
	for _, n := range nicAnnotation {
		result[n.BirthIP] = nicMapValue{n.PCIAddress, n.BirthName}
	}

	return result, nil
}

// getNorthInterfaces returns a map from network to ip.
func getNorthInterfaces(node *corev1.Node, log *logrus.Entry) (map[string]string, error) {
	niAnnotationString, ok := node.GetAnnotations()[networkv1.NorthInterfacesAnnotationKey]
	if !ok {
		return nil, fmt.Errorf("north interfaces annotation does not exist, looking for annotation with key %s, node annotations: %v", networkv1.NorthInterfacesAnnotationKey, node.GetAnnotations())
	}
	result := make(map[string]string)
	if niAnnotationString == "" {
		log.Debugf("North interfaces annotation empty:")
		return result, nil
	}
	niAnnotation, err := networkv1.ParseNorthInterfacesAnnotation(niAnnotationString)
	log.Debugf("North interfaces annotation after parsing: %v", niAnnotation)
	if err != nil {
		return nil, fmt.Errorf("error parsing north interfaces annotation: %v", err)
	}
	for _, n := range niAnnotation {
		result[n.Network] = n.IpAddress
	}

	return result, nil
}

func findInSlice(arr []string, s string) int {
	for i := range arr {
		if arr[i] == s {
			return i
		}
	}
	return -1
}
func findNetworkInSlice(arr []networkv1.Network, s string) int {
	for i := range arr {
		if arr[i].Name == s {
			return i
		}
	}
	return -1
}
func slicesEqual(a1 []string, a2 []string) bool {
	if len(a1) != len(a2) {
		return false
	}
	for i := range a1 {
		if a1[i] == a2[i] {
			return false
		}
	}
	return true
}

// takeDevice adds device to controller map if called with device not already in map.
// Checks if device is in links.
// Only call with devices in the nic-info annotation.
// Idempotent.
func (r *NetworkReconciler) takeDevice(ctx context.Context, dev string, ciliumDevs *[]string, log *logrus.Entry) error {
	log.Debugf("Taking control of device device %s", dev)
	owned, exists := r.controllerManaged[dev]
	if !exists {
		return fmt.Errorf("trying to find dev not in controller cache: %s, %v", dev, r.controllerManaged)
	}
	if owned {
		log.Debugf("We already own device %s, ignoring", dev)
		return nil
	}
	log.Debugf("Taking control of device %s, removing from cilium devs before: %v", dev, *ciliumDevs)
	idx := findInSlice(*ciliumDevs, dev)
	// this check should be unnecessary, as we should never be trying
	// to remove something from the list twice. However, getting it wrong would
	// break us pretty bad so we play it safe here
	if idx != -1 {
		*ciliumDevs = append((*ciliumDevs)[:idx], (*ciliumDevs)[idx+1:]...)
	}
	log.Debugf("Taking control of device %s, removing from cilium devs after: %v", dev, *ciliumDevs)
	r.controllerManaged[dev] = true
	log.Debugf("took control of device device %s", dev)
	return nil
}

// returnDevice adds device to controller map if called with device not already in map.
// Only call with devices in the nic-info annotation.
// Idempotent.
func (r *NetworkReconciler) returnDevice(ctx context.Context, dev string, ciliumDevs *[]string, log *logrus.Entry) error {
	controllerOwned, exists := r.controllerManaged[dev]
	if !exists {
		return fmt.Errorf("trying to find dev not in nic-info: %s", dev)
	}
	if !controllerOwned {
		log.Debugf("Cilium already owns device %s, ignoring", dev)
		return nil
	}
	*ciliumDevs = append(*ciliumDevs, dev)
	r.controllerManaged[dev] = false
	return nil
}
func checkNeedsRename(iface string, nicInfo map[string]nicMapValue, log *logrus.Entry) (bool, string, error) {
	pciAddr, err := nic.ToPCIAddr(iface)
	if err != nil {
		return false, "", fmt.Errorf("unable to find interface %s in sysfs, err: %v", iface, err)
	}
	// map is keyed wrong for us, so we need to do a linear search
	for _, val := range nicInfo {
		mapPciAddr := val.pciAddress
		birthName := val.birthName
		if mapPciAddr == pciAddr {
			return birthName != iface, birthName, nil
		}
	}
	return false, "", fmt.Errorf("device %s is not in nic-info annotation", iface)
}

// reconcileHighPerfNetworks Returns two lists, one of new networks that should be in network-status,
// and one of networks that should not be in network-status.
// Tramples oldNetworkStatus.
// oldNode is read-only
func (r *NetworkReconciler) reconcileHighPerfNetworks(ctx context.Context, oldNetworkStatus map[string]networkv1.NodeNetworkStatus, node *corev1.Node, log *logrus.Entry) ([]string, []string, error) {

	log.Debugf("Node annotations: %s", node.GetAnnotations())
	log.Debugf("north interface annotation: %s", node.GetAnnotations()[networkv1.NorthInterfacesAnnotationKey])

	links, err := netlink.LinkList()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to list links: %v", err)
	}

	northInterfaces, err := getNorthInterfaces(node, log)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get north interfaces: %v", err)
	}
	log.Debugf("got north interfaces: %v", northInterfaces)
	nicInfo, err := getNicInfo(node)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get nic-info: %v", err)
	}
	log.Debugf("got nic info: %v", nicInfo)
	// network names. Will return to indicate what needs updating on the network-status annotation
	toAdd := make([]string, 0)
	toRemove := make([]string, 0)
	// device names. Just for us to track
	ownedDevices := make([]string, 0)
	oldCiliumDevices := option.Config.GetDevices()
	newCiliumDevices := append(make([]string, 0), oldCiliumDevices...)
	for netName, ipAddr := range northInterfaces {
		network := &networkv1.Network{}
		if err := r.Get(ctx, types.NamespacedName{Name: netName}, network); err != nil {
			// Network was likely deleted, we will deal with the iface in the for loop
			// below
			log.WithError(err).Warnf("Network not found but is in north-interfaces, likely deleted")
			continue
		}
		// ignore networks that are not ready or being deleted
		if !checkNetworkAlive(network) {
			continue
		}
		// we delete all entries corresponding to *any* alive Network, not just a Device network
		delete(oldNetworkStatus, network.Name)
		if network.Spec.Type != networkv1.DeviceNetworkType {
			continue
		}
		info, exists := nicInfo[ipAddr]
		if !exists {
			return nil, nil, fmt.Errorf("IP address %s not found in nic-info annotation: %v", ipAddr, nicInfo)
		}
		devName := info.birthName
		if err := r.takeDevice(ctx, devName, &newCiliumDevices, log); err != nil {
			log.Debugf("Error trying to take device %s: %v", devName, err)
			return nil, nil, err
		}
		toAdd = append(toAdd, network.Name)
		ownedDevices = append(ownedDevices, devName)
	}
	for _, link := range links {
		dev := link.Attrs().Name
		isVirt, err := nic.IsVirtual(dev)
		if err != nil {
			return nil, nil, fmt.Errorf("Unable to find interface %s in sysfs: %v", dev, err)
		}
		if isVirt || dev == nic.LoopbackDevName {
			continue
		}
		// TODO(pnaduthota): CNI_DEL could fail and dump an interface with a weird name
		// into our root namespace. Check and rename here
		if findInSlice(ownedDevices, dev) == -1 {
			err := r.returnDevice(ctx, dev, &newCiliumDevices, log)
			if err != nil {
				return nil, nil, err
			}
		}
	}
	// the existing codepaths sort the cilium devices, so we do too
	sort.Strings(newCiliumDevices)
	// only update if we've made a change
	if !slicesEqual(newCiliumDevices, oldCiliumDevices) {
		log.Debugf("Setting cilium devices to %v", newCiliumDevices)
		r.DeviceMgr.ReloadOnDeviceChange(newCiliumDevices)
	}

	// we took out every entry with a Network when looping over north interfaces above,
	// so everything remaining must be stale
	for network := range oldNetworkStatus {
		toRemove = append(toRemove, network)
	}

	log.Debugf("returning from dev-network reconcile: %v, %v.", toAdd, toRemove)
	return toAdd, toRemove, nil
}
