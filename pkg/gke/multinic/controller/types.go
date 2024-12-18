package controller

import (
	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/gke/multinic/types"
	"github.com/cilium/cilium/pkg/trigger"
	"github.com/cilium/statedb"
	"github.com/sirupsen/logrus"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// NetworkReconciler reconciles network objects.
type NetworkReconciler struct {
	client.Client
	EndpointManager endpointmanager.EndpointManager
	NodeName        string
	IPAMMgr         types.MultiNetworkIPAMManager
	DeviceMgr       types.HighPerfDeviceManager
	metricsTrigger  *trigger.Trigger
	Log             *logrus.Entry
	Devices         statedb.Table[*tables.Device]
	DB              *statedb.DB
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
