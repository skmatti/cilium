package v2

type NetworkingEndpoint interface {
	GetName() string
	GetNetworking() *EndpointNetworking
}

var (
	_ NetworkingEndpoint = &CiliumEndpoint{}
)

// GetNetworking returns the endpoint's networking object.
//
// Note: EndpointNetworking may be nil.
func (e *CiliumEndpoint) GetNetworking() *EndpointNetworking {
	return e.Status.Networking
}
