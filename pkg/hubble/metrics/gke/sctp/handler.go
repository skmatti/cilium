// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package sctp

import (
	"context"

	"github.com/prometheus/client_golang/prometheus"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/pkg/hubble/metrics/api"
)

type sctpFlowHandler struct {
	sctpFlows *prometheus.CounterVec
	context   *api.ContextOptions
}

// Init initializes the metric handler by validating and parsing
// the options and then registering all required metrics with the
// specified Prometheus registry
func (h *sctpFlowHandler) Init(registry *prometheus.Registry, options api.Options) error {
	c, err := api.ParseContextOptions(options)
	if err != nil {
		return err
	}
	h.context = c

	labels := []string{"verdict"}
	labels = append(labels, h.context.GetLabelNames()...)

	h.sctpFlows = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: api.DefaultPrometheusNamespace,
		Name:      "sctp_flows_processed_total",
		Help:      "Total number of SCTP flows processed, labeled by verdict (dropped or forwarded).",
	}, labels)

	registry.MustRegister(h.sctpFlows)
	return nil
}

// Status returns the configuration status of the metric handler
func (h *sctpFlowHandler) Status() string {
	return h.context.Status()
}

// Context returns the context used by this metrics handler
func (h *sctpFlowHandler) Context() *api.ContextOptions {
	return h.context
}

// ListMetricVec returns an array of MetricVec used by a handler
func (h *sctpFlowHandler) ListMetricVec() []*prometheus.MetricVec {
	return []*prometheus.MetricVec{h.sctpFlows.MetricVec}
}

// ProcessFlow processes a flow event and performs metrics accounting
func (h *sctpFlowHandler) ProcessFlow(ctx context.Context, flow *flowpb.Flow) error {
	l4 := flow.GetL4()
	if l4 == nil || l4.GetSCTP() == nil {
		return nil
	}

	contextLabels, err := h.context.GetLabelValues(flow)
	if err != nil {
		return err
	}

	labels := []string{flow.GetVerdict().String()}
	labels = append(labels, contextLabels...)

	h.sctpFlows.WithLabelValues(labels...).Inc()
	return nil
}

func __validateInterfaces() {
	var _ api.Handler = &sctpFlowHandler{}
	var _ api.FlowProcessor = &sctpFlowHandler{}
}
