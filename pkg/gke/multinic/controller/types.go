package controller

import (
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
	// invariant: at the end of every reconcile, the keys to this map are every nic listed in
	// nic-info.
	//
	// For every nic where controllerManaged[nic]=true, nic is in the host netns and
	// bpf is unloaded on the device, or the device doesn't exist in host netns (has been moved
	// into pod). The network corresponding to nic is in the network-status annotation
	//
	// For every nic where controllerManaged[nic]=false, the nic is in the hostns, bpf
	// is loaded on nic, and nic is in the cilium devices list.
	controllerManaged map[string]bool
	metricsTrigger    *trigger.Trigger
	Log               *logrus.Entry
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
