package endpoint

// EndpointDeviceType is an enumeration for possible device types of an endpoint.
type EndpointDeviceType string

const (
	// EndpointDeviceVETH is a VETH device, which is the default type for an endpoint.
	// Keeping it empty to be backwards compatible.
	EndpointDeviceVETH = ""
	// EndpointDeviceMACVTAP is a MACVTAP device.
	EndpointDeviceMACVTAP = "macvtap"
	// EndpointDeviceMACVLAN is a MACVLAN device.
	EndpointDeviceMACVLAN = "macvlan"
	// EndpointDeviceIPVLAN is an IPVLAN device.
	EndpointDeviceIPVLAN = "ipvlan"
)
