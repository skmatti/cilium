package flowgen

import (
	"github.com/cilium/cilium/operator/pkg/flowtrace/config"
	"github.com/cilium/cilium/pkg/datapath/linux/config/defines"
	"github.com/cilium/hive/cell"
)

// Cell provides the flowgen functionality.
var Cell = cell.Module(
	"flowgen",
	"Flowgen generates network traffic for testing and debugging",

	cell.Config(config.DefaultConfig),
	cell.Provide(initFlowgen),
)

// initFlowgen initializes the flowgen module based on the provided configuration.
// It returns a NodeOut with defines if flow trace is enabled.
func initFlowgen(cfg config.Config) (out struct {
	cell.Out
	defines.NodeOut
}, err error) {
	if cfg.EnableFlowTrace {
		out.NodeDefines = map[string]string{
			"ENABLE_FLOW_TRACE": "1",
		}
	}
	return out, nil
}
