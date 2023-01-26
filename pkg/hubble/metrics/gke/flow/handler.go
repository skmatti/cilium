package flow

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/prometheus/client_golang/prometheus"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
	"github.com/cilium/cilium/pkg/hubble/metrics/api"
)

type flowHandler struct {
	outcome      *prometheus.CounterVec
	flowsIngress *prometheus.CounterVec
	flowsEgress  *prometheus.CounterVec
	context      *api.ContextOptions
	limiter      map[string]map[string]bool
}

const (
	// PerContextMetricsLimit is limit of data series per context that this handler can create
	PerContextMetricsLimit = 50
	// linuxDefaultEphemeralPortMin is linux default ephemeral port min value.
	// In most linux distros default ephemeral port range is 32768–60999.
	linuxDefaultEphemeralPortMin = 32768
)

// Init initializes and registers prometheus counters.
func (h *flowHandler) Init(registry *prometheus.Registry, options api.Options) error {
	c, err := api.ParseContextOptions(options)
	if err != nil {
		return fmt.Errorf("parse context options failed: %v", err)
	}
	h.context = c

	labels := append(h.labelNames(), h.context.GetLabelNames()...)

	h.outcome = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "pod_flow",
		Name:      "handler",
		Help:      "Total number of flows processed by handler",
	}, []string{"outcome"})

	h.flowsIngress = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "pod_flow",
		Name:      "ingress_flows_count",
		Help:      "Total number of ingress flows processed",
	}, labels)

	h.flowsEgress = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "pod_flow",
		Name:      "egress_flows_count",
		Help:      "Total number of egress flows processed",
	}, labels)

	h.limiter = make(map[string]map[string]bool)

	registry.MustRegister(h.outcome)
	registry.MustRegister(h.flowsIngress)
	registry.MustRegister(h.flowsEgress)
	return nil
}

// Status returns handlers state.
func (h *flowHandler) Status() string {
	return h.context.Status()
}

func (h *flowHandler) Context() *api.ContextOptions {
	return h.context
}

func (h *flowHandler) ListMetricVec() []*prometheus.MetricVec {
	return []*prometheus.MetricVec{h.flowsIngress.MetricVec, h.flowsEgress.MetricVec}
}

// ProcessFlow processes single flow and updates corresponding counters.
func (h *flowHandler) ProcessFlow(ctx context.Context, flow *flowpb.Flow) {
	contextLabelValues, _ := h.context.GetLabelValues(flow)

	if !h.sourceAndDestLabelsSet(contextLabelValues) {
		// do not report metrics without source or destination
		h.outcome.WithLabelValues("context_missing").Inc()
		return
	}

	if counter := h.prometheusCounter(flow); counter != nil {
		labels := h.getLabelValues(flow)

		if !h.canCreateMetricSeries(contextLabelValues, labels) {
			h.outcome.WithLabelValues("limit_exceeded").Inc()
			return
		}

		labels = append(labels, contextLabelValues...)

		counter.WithLabelValues(labels...).Inc()
		h.outcome.WithLabelValues("success").Inc()
	} else {
		h.outcome.WithLabelValues("unknown_direction").Inc()
	}
}

func (h *flowHandler) labelNames() []string {
	return []string{"protocol", "port", "verdict", "verdict_reason", "is_reply", "node_name"}
}

func (h *flowHandler) getLabelValues(flow *flowpb.Flow) []string {
	labelNames := h.labelNames()
	labelValues := make([]string, len(labelNames))
	for i, label := range labelNames {
		labelValues[i] = h.getLabelValue(label, flow)
	}
	return labelValues
}

func (h *flowHandler) getLabelValue(label string, flow *flowpb.Flow) string {
	switch label {
	case "protocol":
		return v1.FlowProtocol(flow)
	case "port":
		return getPortAsString(flow)
	case "verdict":
		return flow.GetVerdict().String()
	case "verdict_reason":
		return getDropReason(flow)
	case "is_reply":
		return isReplyAsString(flow)
	case "node_name":
		return flow.GetNodeName()
	}
	return ""
}

func (h *flowHandler) prometheusCounter(flow *flowpb.Flow) *prometheus.CounterVec {
	switch flow.GetTrafficDirection() {
	case flowpb.TrafficDirection_INGRESS:
		return h.flowsIngress
	case flowpb.TrafficDirection_EGRESS:
		return h.flowsEgress
	default:
		return nil
	}
}

func (h *flowHandler) sourceAndDestLabelsSet(values []string) bool {
	for i, labelName := range h.context.GetLabelNames() {
		if values[i] == "" && (labelName == "source" || labelName == "destination") {
			return false
		}
	}

	return true
}

func (h *flowHandler) canCreateMetricSeries(contextLabels []string, labels []string) bool {
	key := strings.Join(contextLabels[:], "_")
	value := strings.Join(labels[:], "_")

	if k, ok := h.limiter[key]; ok {
		if _, ok := k[value]; ok {
			// data series already exists
			return true
		}
	} else {
		h.limiter[key] = make(map[string]bool)
	}

	if len(h.limiter[key]) >= PerContextMetricsLimit {
		// too many different metrics per context
		return false
	}

	// save labels set as allowed within limit
	h.limiter[key][value] = true
	return true
}

func getPortAsString(flow *flowpb.Flow) string {
	l4 := flow.GetL4()
	isReply := flow.GetIsReply()
	if isReply == nil || l4 == nil {
		return ""
	}

	// If is_reply from source_port else from destination_port.
	if isReply.GetValue() {
		switch l4.Protocol.(type) {
		case *flowpb.Layer4_TCP:
			return nonEphemeralPortAsString(l4.GetTCP().GetSourcePort())
		case *flowpb.Layer4_UDP:
			return nonEphemeralPortAsString(l4.GetUDP().GetSourcePort())
		case *flowpb.Layer4_SCTP:
			return nonEphemeralPortAsString(l4.GetSCTP().GetSourcePort())
		case *flowpb.Layer4_ICMPv4, *flowpb.Layer4_ICMPv6:
			return "0"
		}
	} else {
		switch l4.Protocol.(type) {
		case *flowpb.Layer4_TCP:
			return nonEphemeralPortAsString(l4.GetTCP().GetDestinationPort())
		case *flowpb.Layer4_UDP:
			return nonEphemeralPortAsString(l4.GetUDP().GetDestinationPort())
		case *flowpb.Layer4_SCTP:
			return nonEphemeralPortAsString(l4.GetSCTP().GetDestinationPort())
		case *flowpb.Layer4_ICMPv4, *flowpb.Layer4_ICMPv6:
			return "0"
		}
	}

	return ""
}

// nonEphemeralPortAsString is a naive implementation of checking if port is
// ephemeral. In most linux distros default ephemeral port range is 32768–60999.
func nonEphemeralPortAsString(port uint32) string {
	if port < linuxDefaultEphemeralPortMin {
		return strconv.Itoa(int(port))
	}
	return ""
}

func getDropReason(flow *flowpb.Flow) string {
	if flow.GetVerdict() != flowpb.Verdict_DROPPED {
		return ""
	}
	return flow.GetDropReasonDesc().String()
}

func isReplyAsString(flow *flowpb.Flow) string {
	if flow.GetIsReply() == nil {
		return ""
	}
	if flow.GetIsReply().GetValue() {
		return "true"
	}
	return "false"
}
