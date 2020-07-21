package cmd

import (
	"github.com/cilium/cilium/pkg/gke/nodefirewall"
	"github.com/cilium/cilium/pkg/gke/nodefirewall/types"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/promise"
)

var googleCell = cell.Module(
	"google",
	"Google",

	cell.Provide(newPolicyManagerPromise),
	nodefirewall.Cell,
)

// Converts Daemon promise into a PolicyManager promise
func newPolicyManagerPromise(dp promise.Promise[*Daemon], lc hive.Lifecycle) promise.Promise[types.PolicyManager] {
	pmResolver, pmPromise := promise.New[types.PolicyManager]()
	lc.Append(hive.Hook{
		OnStart: func(hc hive.HookContext) error {
			daemon, err := dp.Await(hc)
			if err != nil {
				return err
			}
			pmResolver.Resolve(daemon)
			return nil
		},
	})
	return pmPromise
}
