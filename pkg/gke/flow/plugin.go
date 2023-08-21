// Copyright 2020 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package plugin

import (
	"context"

	pb "github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/pkg/gke/dispatcher"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/hubble/observer/observeroption"
	"github.com/cilium/cilium/pkg/promise"
)

// Use global variable because hubble server hasn't been modularized
var globalFlowPlugin = FlowPlugin{}

var Cell = cell.Module(
	"flow-plugin",
	"Flow Plugin",

	cell.Provide(newFlowPlugin),
	cell.Invoke(func(p FlowPlugin) { globalFlowPlugin = p }),
)

type FlowPlugin struct {
	HubbleResolver promise.Resolver[observeroption.Server]
	HubblePromise  promise.Promise[observeroption.Server]
	Dispatcher     dispatcher.Dispatcher
	Observer       dispatcher.Observer
}

func GlobalFlowPlugin() FlowPlugin {
	return globalFlowPlugin
}

func newFlowPlugin() FlowPlugin {
	hubbleResolver, hubblePromise := promise.New[observeroption.Server]()
	dispatch := dispatcher.NewDispatcher()
	observer := dispatch.(dispatcher.Observer)
	return FlowPlugin{
		HubbleResolver: hubbleResolver,
		HubblePromise:  hubblePromise,
		Dispatcher:     dispatch,
		Observer:       observer,
	}
}

func (p FlowPlugin) OnServerInit(srv observeroption.Server) error {
	p.HubbleResolver.Resolve(srv)
	return nil
}

func (p FlowPlugin) OnDecodedFlow(ctx context.Context, pb *pb.Flow) (bool, error) {
	return p.Observer.OnDecodedFlow(ctx, pb)
}
