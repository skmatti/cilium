package clustermesh

import (
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/gke/features"
	"github.com/cilium/hive/cell"
)

var googleCell = cell.Module(
	"google",
	"Google",

	features.Cell,
	cell.Config(cmtypes.DefaultGoogleClusterInfo),
)
