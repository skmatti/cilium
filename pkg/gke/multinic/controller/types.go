package controller

import (
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/trigger"
	"github.com/sirupsen/logrus"
	networkv1 "k8s.io/cloud-provider-gcp/crd/apis/network/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// NetworkReconciler reconciles network objects.
type NetworkReconciler struct {
	client.Client
	EndpointManager     EndpointManager
	NodeName            string
	IPAMMgr             ipamManager
	DeviceMgr           deviceManager
	metricsTrigger      *trigger.Trigger
	Log                 *logrus.Entry
	HostEndpointManager HostEndpointManager
	RestoredHostEPs     []*endpoint.Endpoint
}

type ipamManager interface {
	UpdateMultiNetworkIPAMAllocators(annotations map[string]string) error
	ReserveGatewayIP(network *networkv1.Network) error
	AllocateIP(ip, owner string) error
}

type deviceManager interface {
	ReloadOnDeviceChange(devices []string)
}

type nicMapValue struct {
	pciAddress string
	birthName  string
}

// EndpointManager specifies the methods to manage endpoints.
type EndpointManager interface {
	// Subscribe to endpoint manager events.
	Subscribe(endpointmanager.Subscriber)
	// GetEndpoints returns a list of all endpoints.
	GetEndpoints() []*endpoint.Endpoint
	// GetHostEndpoint returns the default host endpoint.
	GetHostEndpoint() *endpoint.Endpoint
}

// HostEndpointManager specifies the methods to manage multi nic endpoints.
type HostEndpointManager interface {
	// EnsureMultiNICHostEndpoint creates a host endpoint for a given network.
	// If the endpoint already exists, the endpoint labels are reinitialized.
	EnsureMultiNICHostEndpoint(restoredHostEPs []*endpoint.Endpoint, network, parentDevice string) (*endpoint.Endpoint, error)
	// DeleteMultiNICHostEndpoint deletes the host endpoint for a given network
	// and parent device.
	DeleteMultiNICHostEndpoint(network, parentDevice string) error
}
