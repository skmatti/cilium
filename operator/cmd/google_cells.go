package cmd

import (
	"github.com/cilium/cilium/operator/pkg/gke/windows"
	"github.com/cilium/cilium/pkg/hive/cell"
)

var googleCell = cell.Module(
	"google-operator",
	"Google Operator",

	windows.Cell,
)
