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

// This is the entry point to GKE-specific functionality. Invoked at daemon startup.

package plugin

import (
	"context"
	"fmt"

	pb "github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/pkg/gke/dispatcher"
	nlcontroller "github.com/cilium/cilium/pkg/gke/networklogging/controller"
	me "github.com/cilium/cilium/pkg/gke/networkpolicy/metrics"
	"github.com/cilium/cilium/pkg/hubble/observer/observeroption"
	"github.com/cilium/cilium/pkg/hubble/parser/getters"
	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

var (
	log = logging.DefaultLogger.WithField(logfields.LogSubsys, "gke-flow-plugin")
)

type gkeFlowPlugin struct {
	networkLoggingController  *nlcontroller.Controller
	metricsExporterController *me.Controller
	endpointGetter            getters.EndpointGetter
	storeGetter               getters.StoreGetter
	dispatcher                dispatcher.Dispatcher
	observer                  dispatcher.Observer
	networkLoggingStopCh      chan struct{}
	metricExporterStopCh      chan struct{}
}

// GKEPlugin provides the functions to be inserted into Hubble processing chain
// defined in pkg/hubble/observer/observeroption/option.go
type GKEFlowPlugin interface {
	// Stop stops the plugin.
	Stop()
	// OnDecodedFlow is invoked after a flow has been decoded at Hubble.
	OnDecodedFlow(ctx context.Context, pb *pb.Flow) (bool, error)
	// OnServerInit is invoked after all Hubble server options have been applied.
	OnServerInit(srv observeroption.Server) error
}

// New
func New() GKEFlowPlugin {
	return &gkeFlowPlugin{}
}

// Stop stops GKEFlowPlugin.
func (p *gkeFlowPlugin) Stop() {
	log.Info("Stop GKE flow plugin")
	close(p.networkLoggingStopCh)
	close(p.metricExporterStopCh)
}

// OnDecodedFlow provides the API to observe Hubble flow.
func (p *gkeFlowPlugin) OnDecodedFlow(ctx context.Context, pb *pb.Flow) (bool, error) {
	return p.observer.OnDecodedFlow(ctx, pb)
}

// OnServerInit initiates GKE flow plugin and triggers the run.
func (p *gkeFlowPlugin) OnServerInit(srv observeroption.Server) error {
	endpointGetter, ok := srv.GetOptions().CiliumDaemon.(getters.EndpointGetter)
	if !ok || endpointGetter == nil {
		err := fmt.Errorf("invalid type, expected endpointGetter, got %T", srv.GetOptions().CiliumDaemon)
		log.Errorf("Error: %v", err)
		return err
	}
	p.endpointGetter = endpointGetter

	storeGetter, ok := srv.GetOptions().CiliumDaemon.(getters.StoreGetter)
	if !ok || storeGetter == nil {
		err := fmt.Errorf("invalid type, expected storeGetter, got %T", srv.GetOptions().CiliumDaemon)
		log.Errorf("Error: %v", err)
		return err
	}
	p.storeGetter = storeGetter

	p.dispatcher = dispatcher.NewDispatcher()
	p.observer = p.dispatcher.(dispatcher.Observer)
	kubeConfig, err := k8s.CreateConfig()
	if err != nil {
		log.Errorf("Failed to create kubernetes config: %v", err)
		return err
	}
	log.Infof("Successfully obtained kubernetes config")

	// networkLoggingstopCh is used to only signal closing. So it doesn't needs any buffer
	// and will only have open and close operations.
	p.networkLoggingStopCh = make(chan struct{})
	p.networkLoggingController, err = nlcontroller.NewController(kubeConfig, p.networkLoggingStopCh, p.dispatcher, p.endpointGetter, p.storeGetter)
	if err != nil {
		log.Errorf("Failed to create network logging controller: %v", err)
		return err
	}
	log.Info("Created network logging controller")

	// metricExporterStopCh is used to only signal closing. So it doesn't needs any buffer
	// and will only have open and close operations.
	p.metricExporterStopCh = make(chan struct{})
	p.metricsExporterController, err = me.NewController(p.dispatcher, p.metricExporterStopCh)
	if err != nil {
		log.Errorf("Failed to create metric exporter controller: %v", err)
		return err
	}
	log.Info("Created metric exporter controller")
	go p.metricsExporterController.Run()
	go p.networkLoggingController.Run()
	return nil
}
