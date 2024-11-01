package cmd

import (
	"fmt"

	"github.com/cilium/cilium/pkg/gke/enhancedservices"
	"github.com/cilium/cilium/pkg/gke/features"
	"github.com/cilium/cilium/pkg/gke/nodefirewall/types"
	"github.com/cilium/cilium/pkg/promise"
	"github.com/cilium/hive/cell"
)

var googleCell = cell.Module(
	"google",
	"Google",

	features.Cell,
	enhancedservices.Cell,

	cell.Provide(newPolicyManagerPromise),
)

// Converts Daemon promise into a PolicyManager promise
func newPolicyManagerPromise(dp promise.Promise[*Daemon], lc cell.Lifecycle) promise.Promise[types.PolicyManager] {
	pmResolver, pmPromise := promise.New[types.PolicyManager]()
	lc.Append(cell.Hook{
		OnStart: func(hc cell.HookContext) error {
			daemon, err := dp.Await(hc)
			if err != nil {
				return err
			}
			pmResolver.Resolve(daemon)
			return nil
		},
		OnStop: func(_ cell.HookContext) error {
			pmResolver.Reject(fmt.Errorf("failed to complete local node discovery"))
			return nil
		},
	})
	return pmPromise
}
