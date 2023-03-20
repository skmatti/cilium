package endpoint

import (
	multinicep "github.com/cilium/cilium/pkg/gke/multinic/endpoint"
	"github.com/cilium/cilium/pkg/mac"
)

func (e *epInfoCache) GetPodStackRedirectIfindex() int {
	return e.podStackRedirectIfindex
}

// IsMultiNIC returns if the endpoint is a multinic endpoint.
func (ep *epInfoCache) IsMultiNIC() bool {
	return ep.deviceType != multinicep.EndpointDeviceVETH
}

// GetDeviceTypeIndex returns multinic endpoint type as int.
func (ep *epInfoCache) GetDeviceTypeIndex() int {
	return ep.deviceTypeIndex
}

// IsMultiNICHost returns if the endpoint is a multinic host endpoint.
func (ep *epInfoCache) IsMultiNICHost() bool {
	return ep.endpoint.IsMultiNICHost()
}

// GetParentDevIndex returns the parent device ifindex.
// Returns 0 if it's not multinic endpoint.
func (ep *epInfoCache) GetParentDevIndex() int {
	if !ep.IsMultiNIC() {
		return 0
	}
	return ep.parentDevIndex
}

// GetParentDevMac returns the mac of the parent device.
// Currently, enabled only for EndpointDeviceMultinicVETH, and returns 00 MAC
// for others.
func (ep *epInfoCache) GetParentDevMac() mac.MAC {
	if ep.deviceType != multinicep.EndpointDeviceMultinicVETH {
		return mac.MAC([]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	}
	return ep.parentDevMac
}

// GetNetworkID returns the network ID of the multinic endpoint.
// Currently, enabled only for EndpointDeviceMultinicVETH, and returns 0
// for others.
func (ep *epInfoCache) GetNetworkID() uint32 {
	if ep.deviceType != multinicep.EndpointDeviceMultinicVETH {
		return 0
	}
	return ep.endpoint.DatapathConfiguration.NetworkID
}

// GetParentDevName returns the parent device name of the endpoint.
func (ep *epInfoCache) GetParentDevName() string {
	return ep.endpoint.GetParentDevName()
}

// IsIPVlan returns if the endpoint is an ipvlan multinic endpoint.
func (ep *epInfoCache) IsIPVlan() bool {
	return ep.deviceType == multinicep.EndpointDeviceIPVLAN
}

// EnableMulticast returns true if the endpoint allows multicast traffic.
func (ep *epInfoCache) EnableMulticast() bool {
	return ep.enableMulticast
}

// DisableSMACVerification returns true if the endpoint wants to skip
// srcMAC verification
func (ep *epInfoCache) DisableSMACVerification() bool {
	return ep.disableSMACVerification
}

func (ep *epInfoCache) initGoogleEndpointInfoCache(e *Endpoint) {
	ep.enableMulticast = e.EnableMulticast()
	ep.disableSMACVerification = e.DisableSMACVerification()
	ep.deviceType = e.GetDeviceType()
	ep.deviceTypeIndex = e.GetDeviceTypeIndex()
	ep.parentDevIndex = e.parentDevIndex
	ep.parentDevMac = e.parentDevMac
	ep.podStackRedirectIfindex = e.podStackRedirectIfindex
}
