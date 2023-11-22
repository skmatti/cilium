package cmd

import (
	"fmt"

	"github.com/cilium/cilium/pkg/gke/endpointqueue"
	"github.com/cilium/cilium/pkg/gke/enhancedservices"
	"github.com/cilium/cilium/pkg/gke/features"
	"github.com/cilium/cilium/pkg/gke/fqdnnetworkpolicy"
	"github.com/cilium/cilium/pkg/gke/imds"
	"github.com/cilium/cilium/pkg/gke/networklogging"
	"github.com/cilium/cilium/pkg/gke/nodefirewall/types"
	"github.com/cilium/cilium/pkg/gke/redirectservice"
	"github.com/cilium/cilium/pkg/gke/servicesteering"
	"github.com/cilium/cilium/pkg/gke/subnet"
	"github.com/cilium/cilium/pkg/gke/trafficsteering"
	"github.com/cilium/cilium/pkg/gke/trafficsteering/controller"
	"github.com/cilium/cilium/pkg/maps/egressmap"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"

	"github.com/cilium/cilium/pkg/gke/remotenode"
	rncontroller "github.com/cilium/cilium/pkg/gke/remotenode/controller"
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
	cell.Provide(newIPCachePromise),
	remotenode.Cell,

	cell.Provide(newPolicyManagerPromise),

	cell.Provide(newLocalNodePromise),
	subnet.Cell,

	cell.Provide(newEndpointCreationSinkPromise),
	cell.Provide(newEgressMapPromise),
	endpointqueue.Cell,

	cell.Provide(newRedirectPolicyManagerPromise),
	redirectservice.Cell,

	networklogging.Cell,
	fqdnnetworkpolicy.Cell,
	trafficsteering.Cell,
	servicesteering.Cell,

	imds.Cell,
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
func newIPCachePromise(dp promise.Promise[*Daemon], lc cell.Lifecycle, config *option.DaemonConfig) promise.Promise[rncontroller.IPCache] {
	rnResolver, rnPromise := promise.New[rncontroller.IPCache]()
	if config.EnableWireguard {
		lc.Append(cell.Hook{
			OnStart: func(hc cell.HookContext) error {
				daemon, err := dp.Await(hc)
				if err != nil {
					return err
				}
				rnResolver.Resolve(daemon.ipcache)
				return nil
			},
			OnStop: func(_ cell.HookContext) error {
				rnResolver.Reject(fmt.Errorf("failed to initialize ipcache"))
				return nil
			},
		})
	}

	return rnPromise
}

// Converts Daemon promise into a EndpointCreationSink promise
func newEndpointCreationSinkPromise(dp promise.Promise[*Daemon], lc cell.Lifecycle) promise.Promise[endpointqueue.EndpointCreationSink] {
	sResolver, sPromise := promise.New[endpointqueue.EndpointCreationSink]()
	lc.Append(cell.Hook{
		OnStart: func(hc cell.HookContext) error {
			daemon, err := dp.Await(hc)
			if err != nil {
				return err
			}
			sResolver.Resolve(daemon)
			return nil
		},
		OnStop: func(_ cell.HookContext) error {
			sResolver.Reject(fmt.Errorf("failed to initialize endpoint creation sink"))
			return nil
		},
	})
	return sPromise
}

func newEgressMapPromise(dp promise.Promise[*Daemon], lc cell.Lifecycle, config *option.DaemonConfig, policyMap egressmap.PolicyMap) promise.Promise[controller.EgressMapInterface] {
	emResolver, emPromise := promise.New[controller.EgressMapInterface]()
	if config.EnableIPv4EgressGateway {
		lc.Append(cell.Hook{
			OnStart: func(hc cell.HookContext) error {
				// Daemon initialization has to complete before egress map is initialized
				if _, err := dp.Await(hc); err != nil {
					return err
				}
				emResolver.Resolve(policyMap)
				return nil
			},
			OnStop: func(_ cell.HookContext) error {
				emResolver.Reject(fmt.Errorf("failed to initialize egress map"))
				return nil
			},
		})
	} else {
		emResolver.Reject(fmt.Errorf("egress map requires %s to be set", option.EnableIPv4EgressGateway))
	}
	return emPromise
}
