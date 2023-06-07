package controller

import (
	"context"

	"github.com/cilium/cilium/pkg/datapath/connector"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/metrics"
	networkv1 "k8s.io/cloud-provider-gcp/crd/apis/network/v1"
)

func (r *NetworkReconciler) EndpointCreated(ep *endpoint.Endpoint) {
	r.metricsTrigger.Trigger()
}

func (r *NetworkReconciler) EndpointDeleted(ep *endpoint.Endpoint, conf endpoint.DeleteConfig) {
	r.metricsTrigger.Trigger()
}

func (r *NetworkReconciler) updateMultiNetMetrics(reasons []string) {
	ctxTimeout, cancel := context.WithTimeout(context.TODO(), listNetworkTimeout)
	defer cancel()

	logger.Debug("Updating multi-network endpoint metrics")

	// Construct a map of network ID -> number of endpoints
	netEpCount := make(map[uint32]int)
	eps := r.EndpointManager.GetEndpoints()
	for _, ep := range eps {
		id := ep.DatapathConfiguration.NetworkID
		netEpCount[id] += 1
	}

	var networkList networkv1.NetworkList
	if err := r.List(ctxTimeout, &networkList); err != nil {
		logger.WithError(err).Warn("Failed to update multi-network endpoint metrics")
		return
	}
	// For each network, export the number of endpoints
	for _, network := range networkList.Items {
		id := connector.GenerateNetworkID(&network)
		netType := string(network.Spec.Type)
		epCount := netEpCount[id]
		metrics.MultiNetworkEndpoint.WithLabelValues(network.Name, netType).Set(float64(epCount))
	}
}
