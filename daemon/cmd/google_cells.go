package cmd

import (
	"github.com/cilium/cilium/pkg/gke/nodefirewall"
	"github.com/cilium/cilium/pkg/gke/nodefirewall/types"
	"github.com/cilium/cilium/pkg/gke/subnet"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/node"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/promise"
)

var googleCell = cell.Module(
	"google",
	"Google",

	cell.Provide(newPolicyManagerPromise),
	cell.Provide(newLocalNodePromise),
	nodefirewall.Cell,
	subnet.Cell,
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

func newLocalNodePromise(dp promise.Promise[*Daemon], lc hive.Lifecycle) promise.Promise[subnet.LocalNodeInfo] {
	nodeResolver, nodePromise := promise.New[subnet.LocalNodeInfo]()
	lc.Append(hive.Hook{
		OnStart: func(hc hive.HookContext) error {
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
	})
	return nodePromise
}
