package flowtrace

import (
	"github.com/cilium/cilium/operator/pkg/flowtrace/config"
	"github.com/cilium/hive/cell"
)

// Cell provides the flow trace functionality.
var Cell = cell.Module(
	"flow-trace",
	"Flow Trace helps debugging connectivity across two endpoints",

	cell.Config(config.DefaultConfig),
)
