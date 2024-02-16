package cmd

import (
	"github.com/cilium/cilium/operator/pkg/gke/synchronizenode"
	"github.com/cilium/cilium/pkg/gke/features"
	"github.com/cilium/cilium/pkg/hive/cell"
)

var googleCell = cell.Module(
	"google-operator",
	"Google Operator",

	synchronizenode.Cell,
	features.Cell,
)
