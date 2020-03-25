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

package policylogger

import (
	"github.com/prometheus/client_golang/prometheus"
)

const (
	// Label values for enforcement.
	enforcementLabelPod  = "pod_policy"
	enforcementLabelNode = "node_policy"

	// Label values for verdict.
	verdictLabelAllow = "allow"
	verdictLabelDeny  = "deny"

	// Label value for error reason.
	// These errors should happen very rarely.
	errorReasonParsing          = "parse_flow_fail"
	errorReasonMarshal          = "json_marshal_fail"
	errorReasonWrite            = "write_disk_fail"
	errorReasonGetNamespace     = "get_namespace_fail"
	errorReasonGetPolicy        = "get_policy_fail"
	errorReasonObjectConversion = "object_conversion_fail"
	errorReasonEvenetQueue      = "flow_queue_drop"
	errorReasonAggregateQueue   = "aggregator_queue_drop"

	// Label value for drop reason.
	// These drops are legitimate on high load situations.
	dropReasonRateLimit   = "rate_limit"
	dropReasonAggregation = "aggregation_limit"
)

// Variables declared for monitoring.
var (
	policyLoggingEnabled = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "",
		Subsystem: "policy_logging",
		Name:      "enabled",
		Help:      "Policy logging configuration.",
	}, []string{"enforcement"})
	policyLoggingReady = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "",
		Subsystem: "policy_logging",
		Name:      "ready",
		Help:      "Whether policy logging is ready on the node.",
	})
	policyLoggingEventCount = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "",
		Subsystem: "policy_logging",
		Name:      "event_count",
		Help:      "Total policy events seen.",
	}, []string{"verdict"})
	policyLoggingErrorCount = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "",
		Subsystem: "policy_logging",
		Name:      "error_count",
		Help:      "Total errors hit for processing policy events.",
	}, []string{"reason"})
	policyLoggingLogCount = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "",
		Subsystem: "policy_logging",
		Name:      "log_count",
		Help:      "Total policy logs written to the disk.",
	}, []string{"enforcement", "verdict"})
	policyLoggingDropCount = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "",
		Subsystem: "policy_logging",
		Name:      "drop_count",
		Help:      "Total policy logs dropped.",
	}, []string{"enforcement", "reason"})
	policyLoggingAllowLatencies = prometheus.NewHistogram(prometheus.HistogramOpts{
		Namespace: "",
		Subsystem: "policy_logging",
		Name:      "allow_latency_microseconds",
		Buckets:   prometheus.ExponentialBuckets(100, 1.5, 16),
		Help:      "Histogram of the time in microseconds from seeing a policy allow event to writing the log to disk.",
	})
	policyLoggingDenyLatencies = prometheus.NewHistogram(prometheus.HistogramOpts{
		Namespace: "",
		Subsystem: "policy_logging",
		Name:      "deny_latency_seconds",
		Buckets:   prometheus.LinearBuckets(5.1, 0.1, 13),
		Help:      "Histogram of the time in seconds from seeing a new policy deny event to writing a log to disk.",
	})
)

func metricsCollectors() []prometheus.Collector {
	return []prometheus.Collector{
		policyLoggingEnabled,
		policyLoggingReady,
		policyLoggingLogCount,
		policyLoggingEventCount,
		policyLoggingErrorCount,
		policyLoggingDropCount,
		policyLoggingAllowLatencies,
		policyLoggingDenyLatencies,
	}
}

func verdictLabel(allow bool) string {
	if allow {
		return verdictLabelAllow
	}
	return verdictLabelDeny
}

func enforcementLabel(isNode bool) string {
	if isNode {
		return enforcementLabelNode
	}
	return enforcementLabelPod
}
