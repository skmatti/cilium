package controller

import (
	networkv1 "github.com/GoogleCloudPlatform/gke-networking-api/apis/network/v1"
	agentK8s "github.com/cilium/cilium/daemon/k8s"
	linuxdatapath "github.com/cilium/cilium/pkg/datapath/linux"
	"github.com/cilium/cilium/pkg/datapath/tables"
	datapath "github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/gke/multinic/multinicconfig"
	"github.com/cilium/cilium/pkg/gke/multinic/types"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/trigger"
	"github.com/cilium/statedb"
	"github.com/sirupsen/logrus"
	"k8s.io/client-go/util/workqueue"
)

// NetworkReconciler reconciles network objects.
type NetworkReconciler struct {
	Clientset         k8sClient.Clientset
	Networks          resource.Resource[*networkv1.Network]
	LocalNodeResource agentK8s.LocalNodeResource
	// handle to an older local node that is used to compare with latest node from a node event
	lastNode *slim_corev1.Node
	// cache of older network objects to compare with and decide if reconciliation is necessary or not
	lastNetworksCache map[string]*networkv1.Network
	// lastNetworksCacheLock protects access to lastNetworksCache.
	lastNetworksCacheLock lock.Mutex
	// workqueue for network reconciliations
	workqueue workqueue.RateLimitingInterface
	// networkErrors is a map of network names to their consecutive failure counts.
	networkErrors map[string]int
	// networkErrorsLock protects access to networkErrors.
	networkErrorsLock   lock.Mutex
	EndpointManager     types.EndpointManager
	NodeName            string
	IPAMMgr             types.MultiNetworkIPAMManager
	DeviceMgr           types.DatapathReloader
	HostEndpointManager types.HostEndpointManager
	RestoredHostEPs     []*endpoint.Endpoint
	MetricsTrigger      *trigger.Trigger
	Log                 *logrus.Entry
	Devices             statedb.Table[*tables.Device]
	DB                  *statedb.DB
	GoogleDeviceManager *linuxdatapath.GoogleDeviceManager
	Loader              datapath.Loader
	Config              multinicconfig.Config
}

type nicMapValue struct {
	pciAddress string
	birthName  string
}
