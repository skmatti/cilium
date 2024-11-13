package cmd

import (
	"fmt"

	"github.com/cilium/cilium/pkg/gke/enhancedservices"
	"github.com/cilium/cilium/pkg/gke/features"
	"github.com/cilium/cilium/pkg/gke/nodefirewall/types"
	"github.com/cilium/cilium/pkg/gke/redirectservice"
	"github.com/cilium/cilium/pkg/gke/subnet"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/promise"
	"github.com/cilium/cilium/pkg/redirectpolicy"
	"github.com/cilium/hive/cell"

	rsController "github.com/cilium/cilium/pkg/gke/redirectservice/controller"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
)

var googleCell = cell.Module(
	"google",
	"Google",

	features.Cell,
	enhancedservices.Cell,

	cell.Provide(newPolicyManagerPromise),

	cell.Provide(newLocalNodePromise),
	subnet.Cell,

	cell.Provide(newRedirectPolicyManagerPromise),
	redirectservice.Cell,
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

func newLocalNodePromise(dp promise.Promise[*Daemon], lc cell.Lifecycle) promise.Promise[subnet.LocalNodeInfo] {
	nodeResolver, nodePromise := promise.New[subnet.LocalNodeInfo]()
	lc.Append(cell.Hook{
		OnStart: func(hc cell.HookContext) error {
			// Daemon initialization has to complete before local node info is populated
			// TODO: Remove after node discovery has been modularized
			if _, err := dp.Await(hc); err != nil {
				return err
			}
			nodeResolver.Resolve(subnet.LocalNodeInfo{
				Name: nodeTypes.GetName(),
				IPv4: node.GetIPv4(),
				IPv6: node.GetIPv6(),
			})
			return nil
		},
		OnStop: func(_ cell.HookContext) error {
			nodeResolver.Reject(fmt.Errorf("failed to complete local node discovery"))
			return nil
		},
	})
	return nodePromise
}

// newRedirectPolicyManagerPromise converts a redirect policy manager into a RedirectPolicyManager promise
func newRedirectPolicyManagerPromise(rdm *redirectpolicy.Manager, lc cell.Lifecycle) promise.Promise[rsController.RedirectPolicyManager] {
	pmResolver, pmPromise := promise.New[rsController.RedirectPolicyManager]()
	lc.Append(cell.Hook{
		OnStart: func(hc cell.HookContext) error {
			pmResolver.Resolve(rdm)
			return nil
		},
	})
	return pmPromise
}
