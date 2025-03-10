package controller

import (
	"context"
	"fmt"
	"net"
	"reflect"

	networkv1 "github.com/GoogleCloudPlatform/gke-networking-api/apis/network/v1"
	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
	"github.com/cilium/cilium/pkg/maps/multinet"
	"github.com/cilium/cilium/pkg/node"
	"github.com/vishvananda/netlink"
	anutils "gke-internal.googlesource.com/anthos-networking/apis/v2/utils"
	"golang.org/x/sys/unix"
)

type hostDevRoutingRecord struct {
	key   multinet.HostDevRoutingKey
	entry multinet.HostDevRoutingEntry
}

func (r *NetworkReconciler) updateHostDeviceRouting(ctx context.Context) error {
	nwStore, err := r.Networks.Store(ctx)
	if err != nil {
		return fmt.Errorf("Failed to fetch network store while updating host device routing entries: %v", err)
	}
	nwList := nwStore.List()
	errs := 0
	desiredRoutingRecs := map[multinet.HostDevRoutingKey]multinet.HostDevRoutingEntry{}
	for _, n := range nwList {
		recs, err := r.hostDevRoutingRecords(n)
		if err != nil {
			errs += 1
			r.Log.WithError(err).Warnf("error determining host device routing records for network %s", n.Name)
		}
		for _, rec := range recs {
			desiredRoutingRecs[rec.key] = rec.entry
		}
	}

	existingRecords, err := existingRoutingRecords()
	if err != nil {
		return fmt.Errorf("unable to fetch existing host device routing records: %v", err)
	}

	for key, value := range desiredRoutingRecs {
		if eval, ok := existingRecords[key]; ok && reflect.DeepEqual(value, eval) {
			continue
		}
		if err := multinet.HostDevRoutingMap.Update(&key, &value); err != nil {
			r.Log.WithError(err).Warnf("could not update host device routing records for key: %v", key)
			errs += 1
		} else {
			r.Log.Infof("successfully updated host device routing record: %v", key)
		}
	}

	for key := range existingRecords {
		if _, ok := desiredRoutingRecs[key]; !ok {
			_, err := multinet.HostDevRoutingMap.SilentDelete(&key)
			if err != nil {
				r.Log.WithError(err).Warnf("could not delete outdated host device routing records: %v", key)
				errs += 1
			} else {
				r.Log.Infof("successfully deleted host device routing record: %v", key)
			}
		}
	}
	if errs > 0 {
		return fmt.Errorf("error while updating host device routing map, will retry")
	}
	return nil
}

// hostDevRoutingRecords builds an in-memory list of the routing records for given network
func (r *NetworkReconciler) hostDevRoutingRecords(n *networkv1.Network) ([]hostDevRoutingRecord, error) {
	if !n.ObjectMeta.DeletionTimestamp.IsZero() {
		return nil, nil
	}
	if networkv1.IsDefaultNetwork(n.Name) || (n.Spec.Type != networkv1.L2NetworkType && n.Spec.Type != networkv1.L3NetworkType) {
		return nil, nil
	}

	// determine parent (host) interface details like ifindex and network address
	// Nodes that are not connected to additional networks will always return error here and
	// there is no way we can recover from this error. Log a warning for such cases and return.
	parentInfName, _, err := anutils.InterfaceInfo(n, node.GetAnnotations())
	if err != nil {
		r.Log.Warnf("could not determine node interface IP, node is probably not connected to the network %s", n.Name)
		return nil, nil
	}
	link, err := safenetlink.LinkByName(parentInfName)
	if err != nil {
		return nil, fmt.Errorf("error finding parent interface %s: %v", parentInfName, err)
	}
	ifIndex := link.Attrs().Index
	ip4Addrs, err := safenetlink.AddrList(link, netlink.FAMILY_V4)
	if err != nil {
		return nil, fmt.Errorf("could not determine node interface IP on link %s: node is probably not connected to the network %s", link.Attrs().Name, n.Name)
	}
	hostDevRoutingRecords := make([]hostDevRoutingRecord, 0)
	// host subnet specific route, next hop is determined by
	// arping for packet's destination IP in L2 networks
	if n.Spec.Type == networkv1.L2NetworkType {
		// dummy next hop
		value := multinet.NewHostDevRoutingEntry(net.IPv4zero)
		for _, addr := range ip4Addrs {
			key := multinet.NewHostDevRoutingKey(uint32(ifIndex), addr.IPNet)
			hostDevRoutingRecords = append(hostDevRoutingRecords, hostDevRoutingRecord{key: *key, entry: *value})
		}
	}

	var nextHopAddr net.IP

	// n.Spec.Gateway4 is usually set in L2/L3 networks for all on-prem (GDC) use cases except when n.Spec.externalDHCP is true.
	// In cases where n.Spec.externalDHCP=true, we currently do not have a way to determine the gateway IP and hence
	// cannot support multinetworking services with externalTrafficPolicy=Cluster.
	// We will revisit this when such a use case arises.
	if n.Spec.Gateway4 != nil {
		nextHopAddr = net.ParseIP(*n.Spec.Gateway4)
		if nextHopAddr == nil {
			return nil, fmt.Errorf("invalid gateway IP for network %s", n.Name)
		}
	} else if n.Spec.Type == networkv1.L3NetworkType && *n.Spec.IPAMMode == networkv1.InternalMode {
		// For GKE, gateway IP is the node network's gateway IP. On the reverse nodeport/LB path, ARP for this gateway IP and
		// route the packet out of the right interface.
		routeList, err := safenetlink.RouteList(link, netlink.FAMILY_V4)
		if err != nil {
			return nil, fmt.Errorf("failed to determine gateway IP for network %s: %w", n.Name, err)
		}
		for _, rt := range routeList {
			if rt.Gw != nil && rt.Table == unix.RT_TABLE_MAIN {
				nextHopAddr = rt.Gw.To4()
				r.Log.Infof("using gateway IP: %s for network %s", nextHopAddr.To4().String(), n.Name)
				break
			}
		}
	}

	if nextHopAddr == nil {
		// TODO(b/366000841): Support L3 traffic on ETP:Cluster services when `externalDHCP: true`
		if n.Spec.ExternalDHCP4 != nil && *n.Spec.ExternalDHCP4 {
			r.Log.Warnf("could not determine the next hop address on link %s, L3 traffic on services will not be supported on network %s", link.Attrs().Name, n.Name)
		} else {
			return nil, fmt.Errorf("failed to determine next hop address IP for network %s", n.Name)
		}
		return hostDevRoutingRecords, nil
	}
	// default route, next hop is gateway
	destPrefix := net.IPNet{
		IP:   net.IPv4zero,
		Mask: net.CIDRMask(0, 8*net.IPv4len),
	}
	key := multinet.NewHostDevRoutingKey(uint32(ifIndex), &destPrefix)
	value := multinet.NewHostDevRoutingEntry(nextHopAddr)
	hostDevRoutingRecords = append(hostDevRoutingRecords, hostDevRoutingRecord{key: *key, entry: *value})
	return hostDevRoutingRecords, nil
}

func existingRoutingRecords() (map[multinet.HostDevRoutingKey]multinet.HostDevRoutingEntry, error) {
	dump := make(map[multinet.HostDevRoutingKey]multinet.HostDevRoutingEntry)
	cb := func(k bpf.MapKey, v bpf.MapValue) {
		key := k.(*multinet.HostDevRoutingKey)
		value := v.(*multinet.HostDevRoutingEntry)
		dump[*key] = *value
	}
	stats := bpf.NewDumpStats(multinet.HostDevRoutingMap)
	err := multinet.HostDevRoutingMap.DumpReliablyWithCallback(cb, stats)
	if err != nil {
		return nil, err
	}
	return dump, nil
}
