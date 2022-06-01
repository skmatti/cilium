package controller

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path"
	"sort"

	"github.com/cilium/cilium/pkg/datapath/loader"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	networkv1 "gke-internal.googlesource.com/anthos-networking/apis/v2/network/v1"
	corev1 "k8s.io/api/core/v1"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/cilium/cilium/pkg/endpointmanager"
)

var (
	logger = logging.DefaultLogger.WithField(logfields.LogSubsys, "gke-multinic-network-controller")
)

// NetworkReconciler reconciles network objects.
type NetworkReconciler struct {
	client.Client
	EndpointManager *endpointmanager.EndpointManager
	NodeName        string
}

const (
	// Directory to store all object files for multinic parent devices.
	multinicObjDir = "/var/run/cilium/state/multinic"
)

func (r *NetworkReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logger.WithField("namespacedName", req.NamespacedName)

	log.Info("Reconciling")

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
		return r.reconcileNetworkDelete(ctx, network, log)
	}

	return r.reconcileNetwork(ctx, network, log)
}

// SetupWithManager configures this controller in the manager.
func (r *NetworkReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if err := os.MkdirAll(multinicObjDir, os.ModePerm); err != nil {
		return err
	}
	return ctrl.NewControllerManagedBy(mgr).
		For(&networkv1.Network{}).Complete(r)
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
	if network.Spec.Type != networkv1.L2NetworkType {
		log.Infof("No need to load ebpf for network type %q", network.Spec.Type)
		return nil
	}
	devToLoad, err := network.InterfaceName()
	if err != nil {
		log.Infof("errored generating interface name for network %s: %s", network.Name, err)
		return nil
	}

	scopedLog := log.WithField(logfields.Interface, devToLoad)
	if isCiliumManaged(devToLoad) {
		scopedLog.Info("The parent interface is already a cilium-managed device. No need to reconcile")
		return nil
	}

	scopedLog.Info("Loading ebpf")
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
	devToUnload, err := network.InterfaceName()
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
func ensureVlanID(network *networkv1.Network, log *logrus.Entry) error {
	if !hasVlanTag(network) {
		return nil
	}

	taggedIntName, err := network.InterfaceName()
	if err != nil {
		log.Errorf("Errored generating interface name for network %s: %s", network.Name, err)
		return nil
	}
	// InterfaceName() will return an error if Spec.NodeInterfaceMatcher.InterfaceName is nil
	parentIntName := *network.Spec.NodeInterfaceMatcher.InterfaceName
	vlanID := int(*network.Spec.L2NetworkConfig.VlanID)
	parentInt, err := netlink.LinkByName(parentIntName)
	if err != nil {
		return fmt.Errorf("failed to find parent interface %s: %q", parentInt, err)
	}
	// check if tagged interface already exists
	link, err := netlink.LinkByName(taggedIntName)
	if err == nil {
		origVlan, ok := link.(*netlink.Vlan)
		if !ok {
			return fmt.Errorf("interface %s is not a vlan (%+v)", taggedIntName, origVlan)
		}

		if origVlan.VlanId != vlanID {
			return fmt.Errorf("existing interface %s has vlan id %d, expected %d", taggedIntName, origVlan.VlanId, vlanID)
		}
		if parentInt.Attrs().Index != origVlan.Attrs().ParentIndex {
			return fmt.Errorf("existing interface %s has parent interface %s, expected %s", taggedIntName, origVlan.Attrs().Name, parentIntName)
		}
	} else {
		vlan := netlink.Vlan{
			LinkAttrs: netlink.LinkAttrs{
				ParentIndex: parentInt.Attrs().Index,
				Name:        taggedIntName,
			},
			VlanId: vlanID,
		}

		if err := netlink.LinkAdd(&vlan); err != nil {
			return fmt.Errorf("failed to create tagged interface %s : %q", taggedIntName, err)
		}
		link = &vlan
	}

	if err := netlink.LinkSetUp(link); err != nil {
		return fmt.Errorf("failed to bring up tagged vlan interface %q: %v", taggedIntName, err)
	}

	log.WithField("vlan", taggedIntName).Info("Ensured vlan interface")
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

func (r *NetworkReconciler) updateNodeNetworkAnnotation(ctx context.Context, networkName string, log *logrus.Entry, isAdd bool) error {
	node := &corev1.Node{}
	if err := r.Get(ctx, types.NamespacedName{Name: r.NodeName}, node); err != nil {
		return fmt.Errorf("failed to get k8s node %q: %v", r.NodeName, err)
	}

	log.WithFields(logrus.Fields{
		logfields.NodeName: r.NodeName,
		"network":          networkName,
	}).Info("Updating node network status annotation")
	netStatusMap, err := getNetworkStatusMap(node)
	if err != nil {
		return fmt.Errorf("failed to get network status map from node %q: %v", r.NodeName, err)
	}
	log.Infof("existing node network status annotation %+v", netStatusMap)

	_, exist := netStatusMap[networkName]
	if isAdd {
		if exist {
			log.Infof("network %q already exists on the node %q", networkName, r.NodeName)
			return nil
		}
		netStatusMap[networkName] = networkv1.NodeNetworkStatus{Name: networkName}
	} else {
		if !exist {
			log.Infof("network %q doesn't exist on the node %q", networkName, r.NodeName)
			return nil
		}
		delete(netStatusMap, networkName)
	}
	log.Infof("node network status annotation to update %+v", netStatusMap)

	if node.Annotations == nil {
		node.Annotations = make(map[string]string)
	}
	node.Annotations[networkv1.NodeNetworkAnnotationKey], err = marshalNodeNetworkAnnotation(netStatusMap)
	if err != nil {
		return fmt.Errorf("failed to marshal node network annotation %v: %v", netStatusMap, err)
	}

	if err := r.Update(ctx, node); err != nil {
		return fmt.Errorf("failed to update k8s node %q: %v", r.NodeName, err)
	}

	log.Info("Updated node network status annotation")
	return nil
}

func (r *NetworkReconciler) reconcileNetwork(ctx context.Context, network *networkv1.Network, log *logrus.Entry) (ctrl.Result, error) {
	if err := ensureVlanID(network, log); err != nil {
		log.WithError(err).Error("Unable to ensure tagged interface")
		return ctrl.Result{}, err
	}
	if err := r.loadEBPFOnParent(ctx, network, log); err != nil {
		log.WithError(err).Error("Unable to load ebpf on parent interface")
		return ctrl.Result{}, err
	}
	if err := r.updateNodeNetworkAnnotation(ctx, network.Name, log, true); err != nil {
		log.WithError(err).Error("Failed to update node network status annotation")
		return ctrl.Result{}, err
	}
	log.Info("Reconciled successfully")
	return ctrl.Result{}, nil
}

func (r *NetworkReconciler) reconcileNetworkDelete(ctx context.Context, network *networkv1.Network, log *logrus.Entry) (ctrl.Result, error) {
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
	if err := r.updateNodeNetworkAnnotation(ctx, network.Name, log, false); err != nil {
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

	taggedIntName, err := network.InterfaceName()
	if err != nil {
		log.Errorf("Errored generating interface name for network %s: %s", network.Name, err)
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
