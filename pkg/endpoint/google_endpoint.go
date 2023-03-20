package endpoint

import (
	"fmt"
	"hash/crc32"

	"github.com/cilium/cilium/pkg/bpf"
	multinicep "github.com/cilium/cilium/pkg/gke/multinic/endpoint"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/mac"
	"github.com/cilium/cilium/pkg/maps/localredirect"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/types"
)

const (
	// MultiNICMapName specifies the tail call map for EP on both egress and ingress used with multinic.
	MultiNICMapName = "cilium_multinic_"
	// maxNameLength is the maximum character length for the CEP object name.
	maxNameLength = 253
)

// IsMultiNIC returns true if the endpoint is a non veth pod endpoint.
func (e *Endpoint) IsMultiNIC() bool {
	return e.deviceType != multinicep.EndpointDeviceVETH && !e.IsMultiNICHost()
}

// IsMultiNICHost returns true if the endpoint is a host multinic endpoint.
func (e *Endpoint) IsMultiNICHost() bool {
	return option.Config.EnableGoogleMultiNICHostFirewall && e.nodeNetworkName != "" && e.IsHost()
}

// IsDefaultHost returns true if the endpoint is the default host endpoint.
func (e *Endpoint) IsDefaultHost() bool {
	return e.IsHost() && (e.nodeNetworkName == "" || e.nodeNetworkName == node.DefaultNodeNetwork)
}

// GetDeviceType returns the device type of the endpoint.
func (e *Endpoint) GetDeviceType() multinicep.EndpointDeviceType {
	return e.deviceType
}

// GetDeviceTypeIndex returns multinic endpoint type as int.
func (e *Endpoint) GetDeviceTypeIndex() int {
	switch e.deviceType {
	case multinicep.EndpointDeviceVETH:
		return multinicep.EndpointDeviceIndexVETH
	case multinicep.EndpointDeviceMultinicVETH:
		return multinicep.EndpointDeviceIndexMultinicVETH
	case multinicep.EndpointDeviceMACVTAP:
		return multinicep.EndpointDeviceIndexMACVTAP
	case multinicep.EndpointDeviceMACVLAN:
		return multinicep.EndpointDeviceIndexMACVLAN
	case multinicep.EndpointDeviceIPVLAN:
		return multinicep.EndpointDeviceIndexIPVLAN
	default:
		return multinicep.EndpointDeviceIndexVETH
	}
}

// SetDeviceTypeForTest sets the device type of the endpoint.
func (e *Endpoint) SetDeviceTypeForTest(t multinicep.EndpointDeviceType) {
	e.deviceType = t
}

// BPFMapPath returns the path to the ipvlan/macvtap/macvlan tail call map of an endpoint.
func (e *Endpoint) BPFMapPath() string {
	return bpf.LocalMapPath(MultiNICMapName, e.ID)
}

// GetInterfaceNameInPod returns the interface name inside the pod namespace.
func (e *Endpoint) GetInterfaceNameInPod() string {
	return e.ifNameInPod
}

// GetNetNS returns the Linux network namespace of the container.
func (e *Endpoint) GetNetNS() string {
	return e.netNs
}

func truncate(s string, length int) string {
	if len(s) <= length {
		return s
	}
	return s[0:length]
}

// suffix returns a string constructed with the given interface name and pod name hash.
// The interface name is kept as much as possible and the fingerprint is generated
// with the pod name using CRC-32 which has 8 character length.
func suffix(ifName, podName string) string {
	return fmt.Sprintf("-%s-%08x", ifName, crc32.ChecksumIEEE([]byte(podName)))
}

// GenerateCEPName generates the CEP name for the endpoint.
// If it's a multi NIC endpoint, the function appends a unique suffix to its pod name.
// The function honors the maximum character length when appending extra suffix.
func (e *Endpoint) GenerateCEPName() string {
	if !e.IsMultiNIC() {
		return e.K8sPodName
	}
	suffix := suffix(e.ifNameInPod, e.K8sPodName)
	return truncate(e.K8sPodName, maxNameLength-len(suffix)) + suffix
}

// GetParentDevIndex returns the parent device ifindex.
// Returns 0 if it's not multinic endpoint.
func (ep *Endpoint) GetParentDevIndex() int {
	if !ep.IsMultiNIC() {
		return 0
	}
	return ep.parentDevIndex
}

// GetParentDevMac returns the mac of the parent device.
// Currently, enabled only for EndpointDeviceMultinicVETH, and returns 00 MAC
// for others.
func (ep *Endpoint) GetParentDevMac() mac.MAC {
	if ep.deviceType != multinicep.EndpointDeviceMultinicVETH {
		return mac.MAC([]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	}
	return ep.parentDevMac
}

func (e *Endpoint) DeleteLocalRedirectMapIfNecessary() error {
	if _, found := e.OpLabels.GetIdentityLabel("remote-redir-from"); found {
		return localredirect.LocalRedirectMap.Delete(
			&localredirect.LocalRedirectKey{Id: uint64(42)},
		)
	}
	return nil
}

func (e *Endpoint) UpdateLocalRedirectMap(newLabels, oldLabels labels.Labels) error {
	var hasOldLabel, hasNewLabel bool
	if oldLabels == nil {
		hasOldLabel = false
	} else {
		_, hasOldLabel = oldLabels["remote-redir-from"]
	}

	_, hasNewLabel = newLabels["remote-redir-from"]

	if hasOldLabel && !hasNewLabel {
		return localredirect.LocalRedirectMap.Delete(
			&localredirect.LocalRedirectKey{Id: 42},
		)
	}
	if hasNewLabel {
		return e.updateLocalRedirectMap(42)
	}
	return nil
}

func (e *Endpoint) updateLocalRedirectMap(key uint64) error {
	var epMac types.MACAddr
	for i, b := range e.LXCMac() {
		epMac[i] = b
	}
	return localredirect.LocalRedirectMap.Update(
		&localredirect.LocalRedirectKey{Id: key},
		&localredirect.LocalRedirectInfo{IfIndex: uint16(e.GetIfIndex()), IfMac: epMac},
	)
}

// GetEpInfoCacheForCurrentDir returns endpoint info cache for the current directory.
func (e *Endpoint) GetEpInfoCacheForCurrentDir() (*epInfoCache, error) {
	if err := e.lockAlive(); err != nil {
		return nil, err
	}
	epInfo := e.createEpInfoCache(e.StateDirectoryPath())
	e.unlock()
	return epInfo, nil
}

// GetPodStackRedirectIfindex returns the ifIndex for the interface which
// can be used to get a packet to the pod-ns from within the pod-ns.
func (e *Endpoint) GetPodStackRedirectIfindex() int {
	return e.podStackRedirectIfindex
}

// ExternalDHCPEnabled returns whether the endpoint has external dhcp enabled.
func (e *Endpoint) ExternalDHCPEnabled() bool {
	return e.externalDHCP4
}

// IsIPVlan returns if the endpoint is a multinic endpoint of type IPVlan.
func (e *Endpoint) IsIPVlan() bool {
	return option.Config.EnableGoogleMultiNIC && e.deviceType == multinicep.EndpointDeviceIPVLAN
}

// EnableMulticast returns true if the endpoint allows multicast traffic.
func (e *Endpoint) EnableMulticast() bool {
	return e.DatapathConfiguration.EnableMulticast
}

// GetNetworkID returns the network ID of the multinic endpoint.
// Currently, enabled only for EndpointDeviceMultinicVETH, and returns 0
// for others.
func (e *Endpoint) GetNetworkID() uint32 {
	if e.deviceType != multinicep.EndpointDeviceMultinicVETH {
		return 0
	}
	return e.DatapathConfiguration.NetworkID
}

// GetParentDevName gets the parent device name.
func (ep *Endpoint) GetParentDevName() string {
	return ep.parentDevName
}

// SetNodeNetworkName sets the host network name.
// If the endpoint is not multi nic host, this does nothing.
func (ep *Endpoint) SetNodeNetworkName(network string) {
	if !option.Config.EnableGoogleMultiNICHostFirewall {
		return
	}
	ep.nodeNetworkName = network
}

// GetNodeNetworkName gets the host network name.
func (ep *Endpoint) GetNodeNetworkName() string {
	return ep.nodeNetworkName
}

// GetHostIdentity gets the host identity.
func (ep *Endpoint) GetHostIdentity() identity.NumericIdentity {
	if !option.Config.EnableGoogleMultiNICHostFirewall {
		return identity.ReservedIdentityHost
	}
	if ep.isHost {
		return ep.getIdentity()
	}
	nodeNetwork := node.GetNodeNetworkForDevice(ep.parentDevName)
	lbl := labels.MultiNICHostLabels(nodeNetwork)[labels.IDNameMultiNICHost]
	id := identity.GetReservedID(lbl.String())
	if id == identity.IdentityUnknown {
		return identity.ReservedIdentityHost
	}
	return id
}
