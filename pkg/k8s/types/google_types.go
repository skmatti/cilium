package types

import v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"

var (
	_ v2.NetworkingEndpoint = &CiliumEndpoint{}
)

// GetNetworking returns the endpoint's networking object.
//
// Note: EndpointNetworking may be nil.
func (e *CiliumEndpoint) GetNetworking() *v2.EndpointNetworking {
	return e.Networking
}
