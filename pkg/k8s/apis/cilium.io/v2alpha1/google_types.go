package v2alpha1

import v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"

var (
	_ v2.NetworkingEndpoint = &CoreCiliumEndpoint{}
)

// GetNetworking returns the endpoint's networking object.
//
// Note: EndpointNetworking may be nil.
func (e *CoreCiliumEndpoint) GetNetworking() *v2.EndpointNetworking {
	return e.Networking
}

// GetName returns the endpoint name.
func (e *CoreCiliumEndpoint) GetName() string {
	return e.Name
}
