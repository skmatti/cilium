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
	EndpointManager *endpointmanager.EndpointManager
	NodeName        string
	IPAMMgr         ipamManager
	DeviceMgr       deviceManager
	metricsTrigger  *trigger.Trigger
	Log             *logrus.Entry
	HostEndpointMgr hostEndpointManager
}

type ipamManager interface {
	UpdateMultiNetworkIPAMAllocators(annotations map[string]string) error
	ReserveGatewayIP(network *networkv1.Network) error
	AllocateIP(ip, owner string) error
}

type deviceManager interface {
	ReloadOnDeviceChange(devices []string)
}

// hostEndpointManager defines methods to manage multi nic host endpoints.
type hostEndpointManager interface {
	// EnsureMultiNICHostEndpoint creates a host endpoint for given network. If
	// the endpoint already exists, the endpoint labels are reinitialized.
	EnsureMultiNICHostEndpoint(network, parentDevice string) (*endpoint.Endpoint, error)
	// DeleteMultiNICHostEndpoint deletes the host endpoint for given network.
	DeleteMultiNICHostEndpoint(network string) error
}

type nicMapValue struct {
	pciAddress string
	birthName  string
}
