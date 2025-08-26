package clustermesh

import (
	"github.com/cilium/hive/cell"

	cmconfig "github.com/cilium/cilium/pkg/clustermesh/config"
	"github.com/cilium/cilium/pkg/gke/features"
)

var googleCell = cell.Module(
	"google",
	"Google",

	features.Cell,
	cell.Config(cmconfig.DefaultGoogleConfig),
)
