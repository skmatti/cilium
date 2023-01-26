// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package api

import (
	"context"
	"strings"

	"github.com/prometheus/client_golang/prometheus"

	pb "github.com/cilium/cilium/api/v1/flow"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

const (
	// DefaultPrometheusNamespace is the default namespace (prefix) used
	// for all Hubble related Prometheus metrics
	DefaultPrometheusNamespace = "hubble"
)

// Map is a set of metrics with their corresponding options
type Map map[string]Options

// ParseMetricList parses a slice of metric options and returns a map of
// enabled metrics
func ParseMetricList(enabledMetrics []string) (m Map) {
	m = Map{}
	for _, metric := range enabledMetrics {
		s := strings.SplitN(metric, ":", 2)
		if len(s) == 2 {
			m[s[0]] = ParseOptions(s[1])
		} else {
			m[s[0]] = Options{}
		}
	}
	return
}

// Handlers is a slice of metric handler
type Handlers []Handler

// Plugin is a metric plugin. A metric plugin is associated a name and is
// responsible to spawn metric handlers of a certain type.
type Plugin interface {
	// NewHandler returns a new metric handler of the respective plugin
	NewHandler() Handler

	// HelpText returns a human readable help text including a description
	// of the options
	HelpText() string
}

// Handler is a metric handler. It is called upon receival of raw event data
// and is responsible to perform metrics accounting according to the scope of
// the metrics plugin.
type Handler interface {
	// Init must initialize the metric handler by validating and parsing
	// the options and then registering all required metrics with the
	// specifies Prometheus registry
	Init(registry *prometheus.Registry, options Options) error

	// ProcessFlow must processes a flow event and perform metrics
	// accounting
	ProcessFlow(ctx context.Context, flow *pb.Flow)

	// ListMetricVec returns an array of MetricVec used by a handler
	ListMetricVec() []*prometheus.MetricVec

	// Context used by this metrics handler
	Context() *ContextOptions

	// Status returns the configuration status of the metric handler
	Status() string
}

// ProcessFlow processes a flow by calling ProcessFlow it on to all enabled
// metric handlers
func (h Handlers) ProcessFlow(ctx context.Context, flow *pb.Flow) {
	for _, mh := range h {
		mh.ProcessFlow(ctx, flow)
	}
}

// ProcessPodDeletion queries all handlers for a list of MetricVec and removes
// metrics directly associated to deleted pod.
func (h Handlers) ProcessPodDeletion(pod *slim_corev1.Pod) {
	for _, handler := range h {
		for _, mv := range handler.ListMetricVec() {
			if ctx := handler.Context(); ctx != nil {
				ctx.DeleteMetricsAssociatedWithPod(pod.GetName(), pod.GetNamespace(), mv)
			}
		}
	}
}

var registry = NewRegistry(
	logging.DefaultLogger.WithField(logfields.LogSubsys, "hubble"),
)

// DefaultRegistry returns the default registry of all available metric plugins
func DefaultRegistry() *Registry {
	return registry
}
