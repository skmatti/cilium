package endpoint

// EndpointDeviceType is an enumeration for possible device types of an endpoint.
type EndpointDeviceType string

const (
	// EndpointDeviceVETH is a VETH device, which is the default type for an endpoint.
	// Keeping it empty to be backwards compatible.
	EndpointDeviceVETH = ""
	// EndpointDeviceMultinicVETH stands for the veth type device for multi-network context.
	EndpointDeviceMultinicVETH = "multinic-veth"
	// EndpointDeviceMACVTAP is a MACVTAP device.
	EndpointDeviceMACVTAP = "macvtap"
	// EndpointDeviceMACVLAN is a MACVLAN device.
	EndpointDeviceMACVLAN = "macvlan"
	// EndpointDeviceIPVLAN is an IPVLAN device.
	EndpointDeviceIPVLAN = "ipvlan"
)

// Corresponding int values to the device types.
// Note this should match the #define equivalant in bpf/lib/google_multinic.h
const (
	EndpointDeviceIndexVETH int = iota
	EndpointDeviceIndexMultinicVETH
	EndpointDeviceIndexMACVTAP
	EndpointDeviceIndexMACVLAN
	EndpointDeviceIndexIPVLAN
)
