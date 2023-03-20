package node

const DefaultNodeNetwork = "node-network"

var (
	// map of parent device and its associated host endpoint ID.
	hostEndpoints       map[string]uint32
	deviceToNodeNetwork map[string]string
	nodeNetworkToDevice map[string]string
)

// GetEndpointIDForParentDevice returns the ID of the host endpoint for the
// given parent device.
// If the map is uninitiazed or the entry does not exist the map, it fall backs
// to the default host endpoint ID.
func GetEndpointIDForParentDevice(parentDevice string) uint32 {
	if hostEndpoints == nil {
		return uint32(GetEndpointID())
	}
	epID, ok := hostEndpoints[parentDevice]
	if !ok {
		return uint32(GetEndpointID())
	}
	return epID
}

// GetNodeNetworkForDevice returns the network for the parent device.
func GetNodeNetworkForDevice(device string) string {
	if deviceToNodeNetwork == nil {
		return DefaultNodeNetwork
	}
	network, ok := deviceToNodeNetwork[device]
	if !ok {
		return DefaultNodeNetwork
	}
	return network
}

// AddMultiNICHost sets the ID of the host endpoint for the given node network.
func AddMultiNICHost(device, nodeNetwork string, id uint32) {
	if hostEndpoints == nil {
		hostEndpoints = make(map[string]uint32)
		deviceToNodeNetwork = make(map[string]string)
		nodeNetworkToDevice = make(map[string]string)
	}
	hostEndpoints[device] = id
	deviceToNodeNetwork[device] = nodeNetwork
	nodeNetworkToDevice[nodeNetwork] = device
}
