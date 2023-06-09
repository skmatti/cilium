package controller

import (
	"context"
	"fmt"
	"reflect"
	"sort"

	"github.com/cilium/cilium/pkg/gke/multinic/nic"
	"github.com/cilium/cilium/pkg/option"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	corev1 "k8s.io/api/core/v1"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/types"
	networkv1 "k8s.io/cloud-provider-gcp/crd/apis/network/v1"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

const (
	// TODO: consider moving to cloud-provider-gcp to share a single definition with NCM
	highPerfFinalizer = "networking.gke.io/high-perf-finalizer"
)

func (r *NetworkReconciler) handleHighPerfNetworks(ctx context.Context, node *corev1.Node, oldNode *corev1.Node) (rerr error) {
	add, remove, err := r.reconcileHighPerfNetworks(ctx, oldNode)
	if err != nil {
		r.Log.WithError(err).Error("Failed to reconcile device-typed networks")
		return err
	}
	for _, a := range add {
		r.Log.Debugf("adding %s to network-status annotation", a)
		if err := addToNodeNetworkStatus(ctx, node, a, "", "", r.Log); err != nil {
			r.Log.WithError(err).Error("Failed to update node network status annotation")
			return err
		}
	}
	for _, a := range remove {
		r.Log.Debugf("removing %s to network-status annotation", a)
		if err := deleteFromNetworkStatus(ctx, node, a, "", "", r.Log); err != nil {
			r.Log.WithError(err).Error("Failed to update node network status annotation")
			return err
		}
	}
	return nil
}

// reconcileHighPerfNetworks Returns two lists, one of new networks that should be in network-status,
// and one of networks that should not be in network-status.
// oldNode is read-only
func (r *NetworkReconciler) reconcileHighPerfNetworks(ctx context.Context, node *corev1.Node) ([]string, []string, error) {
	links, err := netlink.LinkList()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to list links: %v", err)
	}

	northInterfaces, err := getNorthInterfaces(node)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get north interfaces: %v", err)
	}
	r.Log.Infof("Got north interfaces: %v", northInterfaces)
	nicInfo, err := getNicInfo(node)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get nic-info: %v", err)
	}
	r.Log.Infof("Got nic info: %v", nicInfo)
	// network names. Will return to indicate what needs updating on the network-status annotation
	toAdd := make([]string, 0)
	toRemove := make([]string, 0)
	// device names. Just for us to track
	ownedDevices := make([]string, 0)
	oldCiliumDevices := copySlice(option.Config.GetDevices())
	sort.Strings(oldCiliumDevices)
	newCiliumDevices := append(make([]string, 0), oldCiliumDevices...)
	for netName, ipAddr := range northInterfaces {
		network := &networkv1.Network{}
		if err := r.Get(ctx, types.NamespacedName{Name: netName}, network); err != nil {
			if !k8sErrors.IsNotFound(err) {
				return nil, nil, fmt.Errorf("failed to fetch network %s: %v", netName, err)
			}
			// Network was likely deleted, we will deal with the iface in the for loop
			// below
			r.Log.WithError(err).Warnf("Network not found but is in north-interfaces, likely deleted")
			continue
		}
		if network.Spec.Type != networkv1.DeviceNetworkType {
			continue
		}
		// ignore networks that are not ready or being deleted
		if !checkNetworkAlive(network) {
			toRemove = append(toRemove, network.Name)
			r.Log.Infof("Skipped Network %s that is not alive", network.Name)
			continue
		}
		// we delete all entries corresponding to *any* alive Network, not just a Device network
		info, exists := nicInfo[ipAddr]
		if !exists {
			return nil, nil, fmt.Errorf("IP address %s not found in nic-info annotation: %v", ipAddr, nicInfo)
		}
		devName := info.birthName
		if err := r.takeDevice(ctx, devName, &newCiliumDevices); err != nil {
			return nil, nil, fmt.Errorf("failed to take devcie %s: %v", devName, err)
		}
		toAdd = append(toAdd, network.Name)
		ownedDevices = append(ownedDevices, devName)
	}
	for _, link := range links {
		dev := link.Attrs().Name
		isVirt, err := nic.IsVirtual(dev)
		if err != nil {
			return nil, nil, fmt.Errorf("unable to find interface %s in sysfs: %v", dev, err)
		}
		if isVirt || dev == nic.LoopbackDevName {
			continue
		}
		// TODO(pnaduthota): CNI_DEL could fail and dump an interface with a weird name
		// into our root namespace. Check and rename here
		if findInSlice(ownedDevices, dev) == -1 {
			err := r.returnDevice(ctx, dev, &newCiliumDevices)
			if err != nil {
				return nil, nil, err
			}
		}
	}
	// the existing codepaths sort the cilium devices, so we do too
	sort.Strings(newCiliumDevices)
	// only update if we've made a change
	if !reflect.DeepEqual(newCiliumDevices, oldCiliumDevices) {
		r.Log.Infof("Setting cilium devices from %v to %v", oldCiliumDevices, newCiliumDevices)
		r.DeviceMgr.ReloadOnDeviceChange(newCiliumDevices)
	}

	r.Log.Infof("returning from reconcileHighPerfNetworks. toAdd %v, toRemove: %v.", toAdd, toRemove)
	return toAdd, toRemove, nil
}

// takeDevice adds device to controller map if called with device not already in map.
// Checks if device is in links.
// Only call with devices in the nic-info annotation.
// Idempotent.
func (r *NetworkReconciler) takeDevice(ctx context.Context, dev string, ciliumDevs *[]string) error {
	idx := findInSlice(*ciliumDevs, dev)
	// this check should be unnecessary, as we should never be trying
	// to remove something from the list twice. However, getting it wrong would
	// break us pretty bad so we play it safe here
	if idx != -1 {
		*ciliumDevs = append((*ciliumDevs)[:idx], (*ciliumDevs)[idx+1:]...)
		r.Log.Infof("removed %s from cilium devs: %v", dev, *ciliumDevs)
	}
	return nil
}

// Init renames all devices found to their birthname and sets the anetd devices list. Does *not*
// update the annotations.
func (r *NetworkReconciler) RestoreDevices(ctx context.Context, node *corev1.Node) error {
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
	ciliumDevicesList := copySlice(option.Config.GetDevices())
	r.Log.Infof("Existing cilium devices during RestoreDevices: %v", ciliumDevicesList)
	for _, link := range links {
		dev := link.Attrs().Name
		isVirt, err := nic.IsVirtual(dev)
		if err != nil {
			return err
		}
		if isVirt || dev == nic.LoopbackDevName {
			continue
		}
		needsRename, birthname, err := checkNeedsRename(dev, nicInfo, r.Log)
		if err != nil {
			return err
		}
		if needsRename {
			r.Log.Infof("Renaming %s to %s during RestoreDevices", dev, birthname)
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
	r.Log.Infof("Updating cilium devices during RestoreDevices: %v", ciliumDevicesList)
	option.Config.SetDevices(ciliumDevicesList)

	return nil
}

// returnDevice adds device to controller map if called with device not already in map.
// Only call with devices in the nic-info annotation.
// Idempotent.
func (r *NetworkReconciler) returnDevice(ctx context.Context, dev string, ciliumDevs *[]string) error {
	idx := findInSlice(*ciliumDevs, dev)
	if idx == -1 {
		*ciliumDevs = append(*ciliumDevs, dev)
		r.Log.Infof("added %s into cilium devs: %v", dev, *ciliumDevs)
	}
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

// checkNetworkAlive returns if the Device network is "alive" and should be reconciled
// The rules are:
//   * The network has Ready status
//   * AND
//   * The network is not being deleted OR there is still high perf finalizer.
func checkNetworkAlive(network *networkv1.Network) bool {
	return meta.IsStatusConditionTrue(network.Status.Conditions, string(networkv1.NetworkConditionStatusReady)) && (network.ObjectMeta.DeletionTimestamp.IsZero() || controllerutil.ContainsFinalizer(network, highPerfFinalizer))
}
