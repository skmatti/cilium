package controller

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/cilium/cilium/pkg/datapath/connector"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/ipam"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/sirupsen/logrus"
)

const (
	// Index within the IP usage string where the number of used IPs is located.
	usedIPsIndex = 0
	// Expected number of parts in the IP usage string.
	expectedIPUsagePartsCount = 2
)

func (r *NetworkReconciler) EndpointCreated(ep *endpoint.Endpoint) {
	r.MetricsTrigger.Trigger()
}

func (r *NetworkReconciler) EndpointDeleted(ep *endpoint.Endpoint, conf endpoint.DeleteConfig) {
	r.MetricsTrigger.Trigger()
}

func (r *NetworkReconciler) EndpointRestored(ep *endpoint.Endpoint) {
	r.MetricsTrigger.Trigger()
}

// updateIpUsageMetrics updates the IP usage metrics for additional pod networks on the node
func (r *NetworkReconciler) updateIpUsageMetrics(ctx context.Context) error {
	logger.Debug("Updating IP usage metrics on additional pod networks")

	existingAllocators := r.IPAMMgr.GetMultiNetworkIPAMAllocators()
	for networkName, allocator := range existingAllocators {
		if err := r.exportIPUsageForNetwork(networkName, allocator); err != nil {
			logger.WithError(err).Errorf("Failed to collect IP usage for network %s", networkName)
			return err
		}
	}
	return nil
}

// exportIPUsageForNetwork collects IP usage statistics for the given network using its allocator
func (r *NetworkReconciler) exportIPUsageForNetwork(networkName string, allocator ipam.Allocator) error {
	_, status := allocator.Dump()

	logger.WithFields(logrus.Fields{
		"node":       r.NodeName,
		"network":    networkName,
		"ipamStatus": status,
	}).Info("Exporting IP usage metrics")

	// First part of the Status provides IP usage string in the format "used/total", for example " 3/14"
	// Extract the IP usage information from the status.
	ipUsageString := strings.Split(status, " ")[0]
	// Split the IP usage string into its constituent parts.
	usedAndTotalIPs := strings.Split(ipUsageString, "/")
	if len(usedAndTotalIPs) != expectedIPUsagePartsCount {
		return fmt.Errorf("invalid IP usage string: %s", ipUsageString)
	}
	// Convert the used IPs part to an integer.
	usedIPs, err := strconv.Atoi(usedAndTotalIPs[usedIPsIndex])
	if err != nil {
		return fmt.Errorf("failed to parse IP usage: %w", err)
	}

	metrics.IPsUsedPerNetworkOnNode.WithLabelValues(r.NodeName, networkName).Set(float64(usedIPs))
	return nil
}

func (r *NetworkReconciler) UpdateMultiNetMetrics(reasons []string) {
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

	nwStore, err := r.Networks.Store(ctxTimeout)
	if err != nil {
		logger.WithError(err).Warn("Failed to update multi-network endpoint metrics")
		return
	}
	nwList := nwStore.List()
	// For each network, export the number of endpoints
	for _, network := range nwList {
		id := connector.GenerateNetworkID(network)
		netType := string(network.Spec.Type)
		epCount := netEpCount[id]
		metrics.MultiNetworkEndpoint.WithLabelValues(network.Name, netType).Set(float64(epCount))
	}
	if err := r.updateIpUsageMetrics(ctxTimeout); err != nil {
		logger.WithError(err).Warn("Failed to update multi-network IP usage metrics")
	}
}
