package cmd

import (
	"github.com/cilium/cilium/pkg/gke/features"
	"github.com/cilium/hive/cell"
)

var googleCell = cell.Module(
	"google-operator",
	"Google Operator",

	features.Cell,
)
