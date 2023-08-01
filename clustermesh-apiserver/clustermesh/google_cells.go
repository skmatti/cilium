package clustermesh

import (
	"github.com/cilium/cilium/pkg/gke/features"
	"github.com/cilium/hive/cell"
)

var googleCell = cell.Module(
	"google",
	"Google",

	features.Cell,
)
