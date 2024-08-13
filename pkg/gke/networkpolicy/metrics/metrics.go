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

package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
)

// Variables declared for monitoring.
var (
	policyEventCount = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "",
		Subsystem: "policy",
		Name:      "event_count",
		Help:      "Total number of network policy events seen in the dataplane.",
	}, []string{"policy_enforced_namespace", "policy_enforced_pod", "verdict", "workload_name", "workload_kind", "direction"})
)

func metricsCollector() []prometheus.Collector {
	return []prometheus.Collector{
		policyEventCount,
	}
}
