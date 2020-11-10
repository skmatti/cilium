package cmd

import (
	"fmt"

	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/gke/fqdnnetworkpolicy"
	"github.com/cilium/cilium/pkg/gke/nodefirewall"
	"github.com/cilium/cilium/pkg/gke/nodefirewall/types"
	"github.com/cilium/cilium/pkg/gke/redirectservice"
	"github.com/cilium/cilium/pkg/gke/subnet"
	"github.com/cilium/cilium/pkg/gke/trafficsteering"
	"github.com/cilium/cilium/pkg/gke/trafficsteering/controller"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/maps/egressmap"
	"github.com/cilium/cilium/pkg/node"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/promise"

	rsController "github.com/cilium/cilium/pkg/gke/redirectservice/controller"
)

var googleCell = cell.Module(
	"google",
	"Google",

	cell.Provide(newPolicyManagerPromise),
	cell.Provide(newLocalNodePromise),
	cell.Provide(newEgressMapPromise),
	cell.Provide(newRedirectPolicyManagerPromise),
	cell.Provide(newEndpointManagerPromise),
	nodefirewall.Cell,
	subnet.Cell,
	trafficsteering.Cell,
	fqdnnetworkpolicy.Cell,
	redirectservice.Cell,
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
		OnStop: func(_ hive.HookContext) error {
			pmResolver.Reject(fmt.Errorf("failed to initialize policy manager"))
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
		OnStop: func(_ hive.HookContext) error {
			nodeResolver.Reject(fmt.Errorf("failed to complete local node discovery"))
			return nil
		},
	})
	return nodePromise
}

func newEgressMapPromise(dp promise.Promise[*Daemon], lc hive.Lifecycle, config *option.DaemonConfig) promise.Promise[controller.EgressMapInterface] {
	if config.EnableIPv4EgressGateway {
	}
	emResolver, emPromise := promise.New[controller.EgressMapInterface]()
	if config.EnableIPv4EgressGateway {
		lc.Append(hive.Hook{
			OnStart: func(hc hive.HookContext) error {
				// Daemon initialization has to complete before egress map is initialized
				if _, err := dp.Await(hc); err != nil {
					return err
				}
				emResolver.Resolve(egressmap.EgressPolicyMap.Map)
				return nil
			},
			OnStop: func(_ hive.HookContext) error {
				emResolver.Reject(fmt.Errorf("failed to initialize egress map"))
				return nil
			},
		})
	} else {
		emResolver.Reject(fmt.Errorf("egress map requires %s to be set", option.EnableIPv4EgressGateway))
	}
	return emPromise
}

// Converts Daemon promise into a RedirectPolicyManager promise
func newRedirectPolicyManagerPromise(dp promise.Promise[*Daemon], lc hive.Lifecycle) promise.Promise[rsController.RedirectPolicyManager] {
	pmResolver, pmPromise := promise.New[rsController.RedirectPolicyManager]()
	lc.Append(hive.Hook{
		OnStart: func(hc hive.HookContext) error {
			daemon, err := dp.Await(hc)
			if err != nil {
				return err
			}
			pmResolver.Resolve(daemon.redirectPolicyManager)
			return nil
		},
	})
	return pmPromise
}

// Converts Daemon promise into EndpointManager promise
func newEndpointManagerPromise(dp promise.Promise[*Daemon], lc hive.Lifecycle) promise.Promise[*endpointmanager.EndpointManager] {
	emResolver, emPromise := promise.New[*endpointmanager.EndpointManager]()
	lc.Append(hive.Hook{
		OnStart: func(hc hive.HookContext) error {
			daemon, err := dp.Await(hc)
			if err != nil {
				return err
			}
			emResolver.Resolve(daemon.endpointManager)
			return nil
		},
	})
	return emPromise
}
