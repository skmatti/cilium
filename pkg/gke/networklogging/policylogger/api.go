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
	fqdnv1alpha1 "github.com/cilium/cilium/pkg/gke/apis/fqdnnetworkpolicy/v1alpha1"
	"github.com/cilium/cilium/pkg/gke/apis/networklogging/v1alpha1"
	"github.com/cilium/cilium/pkg/gke/dispatcher"
	"github.com/cilium/cilium/pkg/hubble/parser/getters"
	cilium_api_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_networkingv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/networking/v1"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/metrics"
)

var (
	log = logging.DefaultLogger.WithField(logfields.LogSubsys, "gke-policy-logger")
)

// Stores contains references to the resource stores required by the network logging controller.
type Stores struct {
	NamespaceStore                      resource.Store[*slim_corev1.Namespace]
	NetworkPolicyStore                  resource.Store[*slim_networkingv1.NetworkPolicy]
	FQDNNetworkPolicyStore              resource.Store[*fqdnv1alpha1.FQDNNetworkPolicy]
	CiliumNetworkPolicyStore            resource.Store[*cilium_api_v2.CiliumNetworkPolicy]
	CiliumClusterwideNetworkPolicyStore resource.Store[*cilium_api_v2.CiliumClusterwideNetworkPolicy]
}

// Logger is the interface used by network policy logger.
type Logger interface {
	// UpdateLoggingSpec returns whether an update happened.
	UpdateLoggingSpec(spec *v1alpha1.NetworkLoggingSpec) bool
	// Start starts the logger, and returns the error if any and a callback function.
	// The callback function is for the controller to notify the logger that it is
	// ready to watch user configurations.
	Start() (func(), error)
	Stop()
}

// NewLogger create a new network policy logger.
func NewLogger(dispatcher dispatcher.Dispatcher, endpointGetter getters.EndpointGetter, stores *Stores, registry *metrics.Registry, opts ...func(*networkPolicyLogger)) Logger {
	log.Infof("New policy logger")
	n := &networkPolicyLogger{
		dispatcher:     dispatcher,
		endpointGetter: endpointGetter,
		stores:         stores,
		cfg:            &defaultConfig,
		spec:           getLogSpec(nil),
		configFilePath: configFile,
	}

	for _, opt := range opts {
		opt(n)
	}

	registry.MustRegister(metricsCollectors()...)
	policyLoggingReady.Set(0)
	return n
}
