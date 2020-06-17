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

type metricsCollector struct {
	logger                      *networkPolicyLogger
	enabled                     *prometheus.Desc
	allowedConnections          *prometheus.Desc
	deniedConnections           *prometheus.Desc
	generatedLogs               *prometheus.Desc
	rateLimitDroppedLogs        *prometheus.Desc
	rateLimitDroppedConnections *prometheus.Desc
	aggregateFails              *prometheus.Desc
	errors                      *prometheus.Desc
}

func newMetricsCollector(logger *networkPolicyLogger) *metricsCollector {
	return &metricsCollector{
		logger: logger,
		enabled: prometheus.NewDesc(
			prometheus.BuildFQName("policy_logging", "", "enabled"),
			"Whether policy logging is enabled",
			nil, nil,
		),
		allowedConnections: prometheus.NewDesc(
			prometheus.BuildFQName("policy_logging", "", "policy_allowed_connections"),
			"Number of policy allowed connections",
			nil, nil,
		),
		deniedConnections: prometheus.NewDesc(
			prometheus.BuildFQName("policy_logging", "", "policy_denied_connections"),
			"Number of policy denied connections",
			nil, nil,
		),
		generatedLogs: prometheus.NewDesc(
			prometheus.BuildFQName("policy_logging", "", "generated_logs"),
			"Number of generated policy logs",
			nil, nil,
		),
		rateLimitDroppedLogs: prometheus.NewDesc(
			prometheus.BuildFQName("policy_logging", "", "rate_limit_dropped_logs"),
			"Number of policy action logs dropped due to rate limiting",
			nil, nil,
		),
		rateLimitDroppedConnections: prometheus.NewDesc(
			prometheus.BuildFQName("policy_logging", "", "rate_limit_dropped_connections"),
			"Number of un-logged connections due to rate limiting",
			nil, nil,
		),
		aggregateFails: prometheus.NewDesc(
			prometheus.BuildFQName("policy_logging", "", "aggregation_failed_connections"),
			"Number of un-logged connections due to aggregation capacity is reached",
			nil, nil,
		),
		errors: prometheus.NewDesc(
			prometheus.BuildFQName("policy_logging", "", "errors"),
			"Number of errors in the flow processing",
			[]string{"type"}, nil,
		),
	}
}

func (c *metricsCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.enabled
	ch <- c.allowedConnections
	ch <- c.deniedConnections
	ch <- c.generatedLogs
	ch <- c.rateLimitDroppedLogs
	ch <- c.rateLimitDroppedConnections
	ch <- c.aggregateFails
	ch <- c.errors
}

func (c *metricsCollector) Collect(ch chan<- prometheus.Metric) {
	spec := c.logger.getSpec()
	var enabled uint64
	if spec.log {
		enabled = 1
	}
	ch <- prometheus.MustNewConstMetric(
		c.enabled,
		prometheus.GaugeValue,
		float64(enabled),
	)
	ch <- prometheus.MustNewConstMetric(
		c.allowedConnections,
		prometheus.CounterValue,
		float64((&c.logger.counter.allowedConnections).get()),
	)
	ch <- prometheus.MustNewConstMetric(
		c.deniedConnections,
		prometheus.CounterValue,
		float64((&c.logger.counter.deniedConnections).get()),
	)
	ch <- prometheus.MustNewConstMetric(
		c.generatedLogs,
		prometheus.CounterValue,
		float64((&c.logger.counter.generatedLogs).get()),
	)
	ch <- prometheus.MustNewConstMetric(
		c.rateLimitDroppedLogs,
		prometheus.CounterValue,
		float64((&c.logger.counter.rateLimitDroppedLogs).get()),
	)
	ch <- prometheus.MustNewConstMetric(
		c.rateLimitDroppedConnections,
		prometheus.CounterValue,
		float64((&c.logger.counter.rateLimitDroppedConnections).get()),
	)
	ch <- prometheus.MustNewConstMetric(
		c.aggregateFails,
		prometheus.CounterValue,
		float64((&c.logger.counter.aggregateFails).get()),
	)
	ch <- prometheus.MustNewConstMetric(
		c.errors,
		prometheus.CounterValue,
		float64((&c.logger.counter.logWriteFails).get()),
		"log-write-error",
	)
	ch <- prometheus.MustNewConstMetric(
		c.errors,
		prometheus.CounterValue,
		float64((&c.logger.counter.flowParseFails).get()),
		"flow-parsing-error",
	)
	ch <- prometheus.MustNewConstMetric(
		c.errors,
		prometheus.CounterValue,
		float64((&c.logger.counter.typeErrors).get()),
		"type-conversion-error",
	)
	ch <- prometheus.MustNewConstMetric(
		c.errors,
		prometheus.CounterValue,
		float64((&c.logger.counter.storeErrors).get()),
		"object-store-error",
	)
}
