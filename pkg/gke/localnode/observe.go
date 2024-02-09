package localnode

import (
	"context"
	"sync"

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
	var once sync.Once
	next := func(n types.Node) {
		log.Info("Observed LocalNode event")
		if ip := n.GetK8sNodeIP(); ip != nil {
			once.Do(func() {
				localnodeip.SetK8sNodeIP(ip)
				log.Infof("LocalNode IP set to %s", ip)
				close(doneChan)
			})
			if !localnodeip.GetK8sNodeIP().Equal(ip) {
				log.Warnf("LocalNode IP change detected; this change is unsupported by this module. Old/current IP: %s, new IP: %s", localnodeip.GetK8sNodeIP(), ip)
			}
		}
	}
	lc.Append(hive.Hook{
		OnStart: func(ctx hive.HookContext) error {
			subCtx, cancel := context.WithCancel(ctx)
			defer cancel()
			nodeStore.Observe(subCtx, next, func(error) {})
			select {
			case <-doneChan:
			case <-ctx.Done():
				log.Info("Hive context done for observing LocalNode events")
			}
			return nil
		},
	})
}
