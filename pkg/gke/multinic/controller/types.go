package controller

import (
	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/gke/multinic/types"
	"github.com/cilium/cilium/pkg/trigger"
	"github.com/cilium/statedb"
	"github.com/sirupsen/logrus"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// NetworkReconciler reconciles network objects.
type NetworkReconciler struct {
	client.Client
	EndpointManager     types.EndpointManager
	NodeName            string
	IPAMMgr             types.MultiNetworkIPAMManager
	DeviceMgr           types.HighPerfDeviceManager
	HostEndpointManager types.HostEndpointManager
	RestoredHostEPs     []*endpoint.Endpoint
	metricsTrigger      *trigger.Trigger
	Log                 *logrus.Entry
	Devices             statedb.Table[*tables.Device]
	DB                  *statedb.DB
}

type nicMapValue struct {
	pciAddress string
	birthName  string
}
