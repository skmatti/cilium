package endpoint

import multinicep "github.com/cilium/cilium/pkg/gke/multinic/endpoint"

func (e *epInfoCache) GetPodStackRedirectIfindex() int {
	return e.podStackRedirectIfindex
}

// IsMultiNIC returns if the endpoint is a multinic endpoint.
func (ep *epInfoCache) IsMultiNIC() bool {
	return ep.deviceType != multinicep.EndpointDeviceVETH
}

// GetParentDevIndex returns the parent device ifindex.
// Returns 0 if it's not multinic endpoint.
func (ep *epInfoCache) GetParentDevIndex() int {
	if !ep.IsMultiNIC() {
		return 0
	}
	return ep.parentDevIndex
}
