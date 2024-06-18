package node

var (
	// multiNICHostDevices a local cache of all multi nic host devices.
	// This is used for loading bpf on correct host interfaces when multi
	// interface host firewall is enabled.
	multiNICHostDevices map[string]bool

	// Boolean flag to track if endpoint ID is set
	endpointIDIsSet bool = false
)

// IsMultiNICHostDevice returns true if given device in the map.
func IsMultiNICHostDevice(dev string) bool {
	if multiNICHostDevices == nil {
		return false
	}
	_, exists := multiNICHostDevices[dev]
	return exists
}

// AddMultiNICHostDevice adds the multi nic host device.
func AddMultiNICHostDevice(dev string) {
	if multiNICHostDevices == nil {
		multiNICHostDevices = make(map[string]bool)
	}
	multiNICHostDevices[dev] = true
}

// DeleteMultiNICHostDevice deletes the given device from the map.
func DeleteMultiNICHostDevice(dev string) {
	delete(multiNICHostDevices, dev)
}

// IsEndpointIDSet returns whether the endpoint ID has been set.
func IsEndpointIDSet() bool {
	return endpointIDIsSet
}
