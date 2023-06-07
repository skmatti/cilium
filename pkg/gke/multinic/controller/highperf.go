package controller

import (
	"context"
	"fmt"
	"sort"

	"github.com/cilium/cilium/pkg/gke/multinic/nic"
	"github.com/cilium/cilium/pkg/option"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	networkv1 "k8s.io/cloud-provider-gcp/crd/apis/network/v1"
)

func (r *NetworkReconciler) handleHighPerfNetworks(ctx context.Context, node *corev1.Node, oldNode *corev1.Node) (rerr error) {
	oldNetworkStatus, err := getNetworkStatusMap(node)
	add, remove, err := r.reconcileHighPerfNetworks(ctx, oldNetworkStatus, oldNode)
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
// Tramples oldNetworkStatus.
// oldNode is read-only
func (r *NetworkReconciler) reconcileHighPerfNetworks(ctx context.Context, oldNetworkStatus map[string]networkv1.NodeNetworkStatus, node *corev1.Node) ([]string, []string, error) {

	r.Log.Debugf("Node annotations: %s", node.GetAnnotations())
	r.Log.Debugf("north interface annotation: %s", node.GetAnnotations()[networkv1.NorthInterfacesAnnotationKey])

	links, err := netlink.LinkList()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to list links: %v", err)
	}

	northInterfaces, err := getNorthInterfaces(node, r.Log)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get north interfaces: %v", err)
	}
	r.Log.Debugf("got north interfaces: %v", northInterfaces)
	nicInfo, err := getNicInfo(node)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get nic-info: %v", err)
	}
	r.Log.Debugf("got nic info: %v", nicInfo)
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
			r.Log.WithError(err).Warnf("Network not found but is in north-interfaces, likely deleted")
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
		if err := r.takeDevice(ctx, devName, &newCiliumDevices); err != nil {
			r.Log.Debugf("Error trying to take device %s: %v", devName, err)
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
			err := r.returnDevice(ctx, dev, &newCiliumDevices)
			if err != nil {
				return nil, nil, err
			}
		}
	}
	// the existing codepaths sort the cilium devices, so we do too
	sort.Strings(newCiliumDevices)
	// only update if we've made a change
	if !slicesEqual(newCiliumDevices, oldCiliumDevices) {
		r.Log.Debugf("Setting cilium devices to %v", newCiliumDevices)
		r.DeviceMgr.ReloadOnDeviceChange(newCiliumDevices)
	}

	// we took out every entry with a Network when looping over north interfaces above,
	// so everything remaining must be stale
	for network := range oldNetworkStatus {
		toRemove = append(toRemove, network)
	}

	r.Log.Debugf("returning from dev-network reconcile: %v, %v.", toAdd, toRemove)
	return toAdd, toRemove, nil
}

// takeDevice adds device to controller map if called with device not already in map.
// Checks if device is in links.
// Only call with devices in the nic-info annotation.
// Idempotent.
func (r *NetworkReconciler) takeDevice(ctx context.Context, dev string, ciliumDevs *[]string) error {
	r.Log.Debugf("Taking control of device device %s", dev)
	owned, exists := r.controllerManaged[dev]
	if !exists {
		return fmt.Errorf("trying to find dev not in controller cache: %s, %v", dev, r.controllerManaged)
	}
	if owned {
		r.Log.Debugf("We already own device %s, ignoring", dev)
		return nil
	}
	r.Log.Debugf("Taking control of device %s, removing from cilium devs before: %v", dev, *ciliumDevs)
	idx := findInSlice(*ciliumDevs, dev)
	// this check should be unnecessary, as we should never be trying
	// to remove something from the list twice. However, getting it wrong would
	// break us pretty bad so we play it safe here
	if idx != -1 {
		*ciliumDevs = append((*ciliumDevs)[:idx], (*ciliumDevs)[idx+1:]...)
	}
	r.Log.Debugf("Taking control of device %s, removing from cilium devs after: %v", dev, *ciliumDevs)
	r.controllerManaged[dev] = true
	r.Log.Debugf("took control of device device %s", dev)
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
		needsRename, birthname, err := checkNeedsRename(dev, nicInfo, r.Log)
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
	r.Log.Infof("initialized map with current device state: %v", r.controllerManaged)

	return nil
}

// returnDevice adds device to controller map if called with device not already in map.
// Only call with devices in the nic-info annotation.
// Idempotent.
func (r *NetworkReconciler) returnDevice(ctx context.Context, dev string, ciliumDevs *[]string) error {
	controllerOwned, exists := r.controllerManaged[dev]
	if !exists {
		return fmt.Errorf("trying to find dev not in nic-info: %s", dev)
	}
	if !controllerOwned {
		r.Log.Debugf("Cilium already owns device %s, ignoring", dev)
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
