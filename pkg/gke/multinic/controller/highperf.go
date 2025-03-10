package controller

import (
	"context"
	"fmt"

	networkv1 "github.com/GoogleCloudPlatform/gke-networking-api/apis/network/v1"
	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
	"github.com/cilium/cilium/pkg/gke/multinic/nic"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/util/rand"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

const (
	// TODO: consider moving to cloud-provider-gcp to share a single definition with NCM
	highPerfFinalizer = "networking.gke.io/high-perf-finalizer"
)

func (r *NetworkReconciler) handleHighPerfNetworks(ctx context.Context, node *slim_corev1.Node, oldNode *slim_corev1.Node) (rerr error) {
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
func (r *NetworkReconciler) reconcileHighPerfNetworks(ctx context.Context, node *slim_corev1.Node) ([]string, []string, error) {
	northInterfaces, err := getNorthInterfaces(node)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get north interfaces: %v", err)
	}
	r.Log.Infof("Got north interfaces: %v", northInterfaces)
	nicAnnotationString, ok := node.GetAnnotations()[networkv1.NICInfoAnnotationKey]
	if !ok {
		return nil, nil, fmt.Errorf("nic-info annotation does not exist, looking for annotation with key %s", networkv1.NICInfoAnnotationKey)
	}
	if nicAnnotationString == "" {
		return nil, nil, fmt.Errorf("nic-info annotation is empty")
	}
	nicAnnotation, err := networkv1.ParseNICInfoAnnotation(nicAnnotationString)
	if err != nil {
		return nil, nil, fmt.Errorf("error parsing nic-info annotation: %v", err)
	}
	nicInfo, err := getNicInfo(nicAnnotation)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get nic-info: %v", err)
	}
	// network names. Will return to indicate what needs updating on the network-status annotation
	toAdd := make([]string, 0)
	toRemove := make([]string, 0)
	aliveDevicePCIAddrs := map[string]any{}
	nwStore, err := r.Networks.Store(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to fetch networks store: %v", err)
	}
	for netName, ipAddr := range northInterfaces {
		network, exists, err := nwStore.GetByKey(resource.Key{Name: netName})
		if err != nil {
			return nil, nil, fmt.Errorf("failed to fetch network %s: from store %v", netName, err)
		}
		if !exists {
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
		info, exists := nicInfo[ipAddr]
		if !exists {
			return nil, nil, fmt.Errorf("IP address %s not found in nic-info annotation: %v", ipAddr, nicInfo)
		}
		aliveDevicePCIAddrs[info.pciAddress] = info.birthName
		toAdd = append(toAdd, network.Name)
	}
	r.Log.Infof("Excluding Device typed networks from cilium management: %v", aliveDevicePCIAddrs)
	needReload, err := r.GoogleDeviceManager.ExcludeDevices(aliveDevicePCIAddrs)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to exclude devices: %v", err)
	}
	if needReload {
		r.Log.Info("Reloading datapath")
		wg, err := r.DeviceMgr.TriggerReload("device-network-exclusion")
		if err != nil {
			return nil, nil, fmt.Errorf("failed to reload datapath: %v", err)
		}
		wg.Wait()
	}

	r.Log.Infof("returning from reconcileHighPerfNetworks. toAdd %v, toRemove: %v.", toAdd, toRemove)
	return toAdd, toRemove, nil
}

// Init renames all devices found to their birthname and sets the anetd devices list. Does *not*
// update the annotations.
func (r *NetworkReconciler) RestoreDevices(ctx context.Context, nicInfoAnn *networkv1.NICInfoAnnotation) error {
	links, err := safenetlink.LinkList()
	if err != nil {
		return fmt.Errorf("failed to list links: %v", err)
	}
	nicInfo, err := getNicInfo(*nicInfoAnn)
	if err != nil {
		return fmt.Errorf("failed to get nic-info: %v", err)
	}

	devsToRename := map[string]netlink.Link{}
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
			// the device could have had an altname applied from when we did a rename
			// in CNI_ADD if we're on ubuntu. DEL removes it normally, but
			// need to recover here if anetd restarts in the middle
			output, err := nic.RemoveAltnameFromInterface(dev, birthname)
			if err != nil {
				r.Log.Infof("Failed removing altname from device %s, expected on COS. err: %v, output: %s", birthname, err, output)
			}
			// Before renaming back to birthName, rename to a tmp name to avoid naming conflict
			tempName := nic.TempDevPrefix + fmt.Sprint(rand.Intn(1000000))
			if err := setLinkName(link, tempName); err != nil {
				return err
			}
			devsToRename[birthname] = link
		}
	}
	for birthname, link := range devsToRename {
		r.Log.Infof("Renaming %s to %s during RestoreDevices", link.Attrs().Name, birthname)
		if err := setLinkName(link, birthname); err != nil {
			return err
		}
		if err = netlink.LinkSetUp(link); err != nil {
			return fmt.Errorf("unable to turn device %s up, err: %v", link, err)
		}
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
	return nil
}

// getNicInfo returns a map from ip to pciaddress, birth name.
func getNicInfo(nicAnnotation networkv1.NICInfoAnnotation) (map[string]nicMapValue, error) {
	result := make(map[string]nicMapValue)
	for _, n := range nicAnnotation {
		result[n.BirthIP] = nicMapValue{n.PCIAddress, n.BirthName}
	}

	return result, nil
}

// checkNetworkAlive returns if the Device network is "alive" and should be reconciled
// The rules are:
//   - The network has Ready status
//   - AND
//   - The network is not being deleted OR there is still high perf finalizer.
func checkNetworkAlive(network *networkv1.Network) bool {
	return meta.IsStatusConditionTrue(network.Status.Conditions, string(networkv1.NetworkConditionStatusReady)) && (network.ObjectMeta.DeletionTimestamp.IsZero() || controllerutil.ContainsFinalizer(network, highPerfFinalizer))
}
