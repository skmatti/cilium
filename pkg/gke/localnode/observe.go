package localnode

import (
	"github.com/cilium/cilium/pkg/gke/localnodeip"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/node/types"
)

var log = logging.DefaultLogger.WithField(logfields.LogSubsys, "google-local-node")
var Cell = cell.Module(
	"local-node",
	"Local Node",

	cell.Invoke(observeLocalNodeIP),
)

// Add a lifecycle hook that observes the local node to populate node IP.
// NOTE: This does not handle node IPs changing without restart.
func observeLocalNodeIP(nodeStore node.LocalNodeStore, lc hive.Lifecycle) {
	doneChan := make(chan struct{})
	next := func(n types.Node) {
		ip := n.GetK8sNodeIP()
		if ip != nil {
			log.Infof("Setting local node IP to %s", ip)
			localnodeip.SetK8sNodeIP(ip)
			close(doneChan)
		}
	}
	lc.Append(hive.Hook{
		OnStart: func(ctx hive.HookContext) error {
			nodeStore.Observe(ctx, next, func(error) {})
			select {
			case <-doneChan:
			case <-ctx.Done():
			}
			return nil
		},
	})
}
