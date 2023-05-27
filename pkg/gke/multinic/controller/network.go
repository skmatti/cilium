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

	"github.com/cilium/cilium/pkg/datapath/loader"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"go.uber.org/multierr"
	corev1 "k8s.io/api/core/v1"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	networkv1 "k8s.io/cloud-provider-gcp/crd/apis/network/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/source"

	"github.com/cilium/cilium/pkg/endpointmanager"
	multinictypes "github.com/cilium/cilium/pkg/gke/multinic/types"
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
}

type ipamManager interface {
	UpdateMultiNetworkIPAMAllocators(annotations map[string]string) error
}

const (
	// Directory to store all object files for multinic parent devices.
	multinicObjDir = "/var/run/cilium/state/multinic"
)

func (r *NetworkReconciler) Reconcile(ctx context.Context, req ctrl.Request) (_ ctrl.Result, rerr error) {
	if !option.Config.EnableGoogleMultiNIC {
		return ctrl.Result{}, nil
	}
	log := logger.WithField("namespacedName", req.NamespacedName)

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
func (r *NetworkReconciler) loadEBPFOnParent(ctx context.Context, network *networkv1.Network, log *logrus.Entry) error {
	if r.EndpointManager == nil {
		log.Info("EndpointManager is nil. Please make sure the reconciler is initialized successfully")
		return nil
	}
	if networkv1.IsDefaultNetwork(network.Name) {
		log.Infof("No need to load ebpf for default network: %v", network.Name)
		return nil
	}
	devToLoad, err := multinictypes.InterfaceName(network)
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

func (r *NetworkReconciler) unloadEBPFOnParent(ctx context.Context, network *networkv1.Network, log *logrus.Entry) error {
	devToUnload, err := multinictypes.InterfaceName(network)
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
		return fmt.Errorf("Failed to remove multinic object dir: %v", err)
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
	annotation, exist := node.Annotations[networkv1.NodeNetworkAnnotationKey]
	if !exist {
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
	// Remove network from node if we fail along the way.
	if err := deleteNodeNetworkAnnotation(ctx, node, network.Name, "", "", log); err != nil {
		log.WithError(err).Error("Failed to update node network status annotation")
		return ctrl.Result{}, err
	}
	if err := ensureInterface(network, log); err != nil {
		log.WithError(err).Error("Unable to ensure network interface")
		return ctrl.Result{}, err
	}
	if err := r.loadEBPFOnParent(ctx, network, log); err != nil {
		log.WithError(err).Error("Unable to load ebpf on parent interface")
		return ctrl.Result{}, err
	}
	// Obtain ip/subnet for node network
	ipv4, ipv6, err := obtainSubnet(network, log)
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
	log.Info("Reconciled successfully")
	return ctrl.Result{}, nil
}

func (r *NetworkReconciler) reconcileNetworkDelete(ctx context.Context, node *corev1.Node, network *networkv1.Network, log *logrus.Entry) (_ ctrl.Result, rerr error) {
	inUseAnn := network.Annotations[networkv1.NetworkInUseAnnotationKey]
	if inUseAnn == networkv1.NetworkInUseAnnotationValTrue {
		log.Infof("Network %q is still in use, exit reconciliation", network.Name)
		return ctrl.Result{}, nil
	}
	if err := r.unloadEBPFOnParent(ctx, network, log); err != nil {
		log.WithError(err).Error("Unable to unload ebpf on parent interface")
		return ctrl.Result{}, err
	}
	if err := deleteVlanID(network, log); err != nil {
		log.WithError(err).Errorf("Unable to delete tagged interface")
		return ctrl.Result{}, err
	}
	if err := updateNodeNetworkAnnotation(ctx, node, network.Name, "", "", log, false); err != nil {
		log.WithError(err).Error("Failed to update node network status annotation")
		return ctrl.Result{}, err
	}
	log.Info("Reconciled on networkDelete successfully")
	return ctrl.Result{}, nil
}

// deleteVlanID deletes the specified vlan tag in the the Network CR if
// lifecycle is AnthosManaged
func deleteVlanID(network *networkv1.Network, log *logrus.Entry) error {
	if !hasVlanTag(network) {
		return nil
	}

	taggedIntName, err := multinictypes.InterfaceName(network)
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
	intfName, err := multinictypes.InterfaceName(network)
	if err != nil {
		// Log error but return nil here as this is mostly due to misconfiguration
		// in the network CR object and is unlikely to reconcile.
		log.Errorf("ensureInterface: Errored generating interface name for network %s: %v", network.Name, err)
		return nil
	}
	scopedLog := log.WithField(logfields.Interface, intfName)

	// InterfaceName() will return an error if Spec.NodeInterfaceMatcher.InterfaceName is nil
	parentIntName := *network.Spec.NodeInterfaceMatcher.InterfaceName
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

func obtainSubnet(network *networkv1.Network, log *logrus.Entry) (string, string, error) {
	_, err := multinictypes.InterfaceName(network)
	if err != nil {
		// Log error but return nil here as this is mostly due to misconfiguration
		// in the network CR object and is unlikely to reconcile.
		log.Errorf("obtainSubnet: Errored generating interface name for network %s: %v", network.Name, err)
		return "", "", nil
	}

	// InterfaceName() will return an error if Spec.NodeInterfaceMatcher.InterfaceName is nil
	parentIntName := *network.Spec.NodeInterfaceMatcher.InterfaceName
	link, err := netlink.LinkByName(parentIntName)
	if err != nil {
		return "", "", fmt.Errorf("failed to find parent interface %s: %q", parentIntName, err)
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
