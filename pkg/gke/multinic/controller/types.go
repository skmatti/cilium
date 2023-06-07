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
	metricsTrigger  *trigger.Trigger
	Log             *logrus.Entry
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
