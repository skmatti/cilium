package cmd

import (
	"github.com/cilium/cilium/operator/pkg/flowtrace"
	"github.com/cilium/cilium/operator/pkg/gke/networking"
	"github.com/cilium/cilium/operator/pkg/gke/synchronizenode"
	"github.com/cilium/cilium/pkg/gke/features"
	"github.com/cilium/hive/cell"
)

var googleCell = cell.Module(
	"google-operator",
	"Google Operator",

	synchronizenode.Cell,
	features.Cell,

	// FlowTrace Cell provides the flow trace functionality, it is disabled by default.
	flowtrace.Cell,

	// gke-networking cell to provide clientset for gke NetworkInterface CR.
	networking.Cell,
)
