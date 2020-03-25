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

// This file acts as a controller for running network policy metric exporter

package metrics

import (
	"github.com/cilium/cilium/pkg/gke/dispatcher"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

var (
	log = logging.DefaultLogger.WithField(logfields.LogSubsys, "gke-network-policy-metrics")
)

// Controller is a struct that is used for providing a control mechanism to pkg/gke/flow/plugin.go over
// metric exporter
type Controller struct {
	dispatcher dispatcher.Dispatcher // dispatcher is used for registering flowListener by exporter
	stopCh     chan struct{}         // stopCh is used for receiving stop signal from plugin and then stopping the exporter go routine

	exporter *exporter // exporter is reference to metric exporter used for control operations
}

// NewController is used for controller object creation
func NewController(dispatcher dispatcher.Dispatcher, stopCh chan struct{}) (*Controller, error) {
	c := &Controller{
		dispatcher: dispatcher,
		exporter:   newExporter(dispatcher),
		stopCh:     stopCh,
	}
	return c, nil
}

// Run is used for performing start & stop operation controls on metric exporter
func (c *Controller) Run() {
	log.Info("Starting network policy metric exporter controller")
	err := c.exporter.start()
	if err != nil {
		log.Errorf("Failed to start network policy metric exporter: %v", err)
		return
	}
	log.Info("Successfully started network policy metric exporter controller")

	// Stop exporter once you receive info on stopCh
	<-c.stopCh
	c.exporter.stop()
	log.Info("Stopping network policy metric exporter controller")
}
