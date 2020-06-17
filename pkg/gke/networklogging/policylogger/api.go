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

// This file holds the entry point for network policy logger.
package policylogger

import (
	"github.com/cilium/cilium/pkg/gke/apis/networklogging/v1alpha1"
	"github.com/cilium/cilium/pkg/gke/dispatcher"
	"github.com/cilium/cilium/pkg/hubble/parser/getters"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/metrics"
)

var (
	log = logging.DefaultLogger.WithField(logfields.LogSubsys, "gke-policy-logger")
)

// Logger is the interface used by network policy logger.
type Logger interface {
	// UpdateLoggingSpec returns error and whether an update happened.
	UpdateLoggingSpec(spec *v1alpha1.NetworkLoggingSpec) (error, bool)
}

// NewLogger create a new network policy logger.
func NewLogger(dispatcher dispatcher.Dispatcher, endpointGetter getters.EndpointGetter, storeGetter getters.StoreGetter) Logger {
	log.Infof("New policy logger")
	n := &networkPolicyLogger{
		dispatcher:       dispatcher,
		policyCorrelator: &policyCorrelation{endpointGetter: endpointGetter},
		storeGetter:      storeGetter,
		cfg:              &defaultConfig,
		spec:             getLogSpec(nil),
	}
	n.metricsCollector = newMetricsCollector(n)
	metrics.MustRegister(n.metricsCollector)
	return n
}
