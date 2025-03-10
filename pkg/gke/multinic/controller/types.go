package controller

import (
	networkv1 "github.com/GoogleCloudPlatform/gke-networking-api/apis/network/v1"
	agentK8s "github.com/cilium/cilium/daemon/k8s"
	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/gke/multinic/types"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/trigger"
	"github.com/cilium/statedb"
	"github.com/sirupsen/logrus"
)

// NetworkReconciler reconciles network objects.
type NetworkReconciler struct {
	Clientset         k8sClient.Clientset
	Networks          resource.Resource[*networkv1.Network]
	LocalNodeResource agentK8s.LocalNodeResource
	// handle to an older local node that is used to compare with latest node from a node event
	lastNode *slim_corev1.Node
	// cache of older network objects to compare with and decide if reconciliation is necessary or not
	lastNetworksCache   map[string]*networkv1.Network
	EndpointManager     types.EndpointManager
	NodeName            string
	IPAMMgr             types.MultiNetworkIPAMManager
	DeviceMgr           types.HighPerfDeviceManager
	HostEndpointManager types.HostEndpointManager
	RestoredHostEPs     []*endpoint.Endpoint
	MetricsTrigger      *trigger.Trigger
	Log                 *logrus.Entry
	Devices             statedb.Table[*tables.Device]
	DB                  *statedb.DB
}

type nicMapValue struct {
	pciAddress string
	birthName  string
}
