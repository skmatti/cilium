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
	"time"

	"github.com/cilium/cilium/api/v1/flow"
)

const (
	ConnectionDirectionIngress = "ingress"
	ConnectionDirectionEgress  = "egress"
	PolicyDispositionAllow     = "allow"
	PolicyDispositionDeny      = "deny"
)

// Connection stores the flow tuples.
type Connection struct {
	SrcIP     string `json:"src_ip"`
	DestIP    string `json:"dest_ip"`
	SrcPort   uint16 `json:"src_port,omitempty"`
	DestPort  uint16 `json:"dest_port,omitempty"`
	Protocol  string `json:"protocol"`
	Direction string `json:"direction"`
}

// Workload stores the workload info. If the workload can be found
// as a pod, PodName and PodNamespace are put into the structure. If the
// workload can be found as a node, NodeName is put into the structure.
// Otherwise, IP is stored in the Instance field.
type Workload struct {
	PodName      string `json:"pod_name,omitempty"`
	NodeName     string `json:"node_name,omitempty"`
	WorkloadKind string `json:"workload_kind,omitempty"`
	WorkloadName string `json:"workload_name,omitempty"`
	PodNamespace string `json:"pod_namespace,omitempty"`
	Namespace    string `json:"namespace,omitempty"`
	Instance     string `json:"instance,omitempty"`
}

// PolicyActionLogEntry is the exportable policy action logging
// entry.
type PolicyActionLogEntry struct {
	Connection  Connection     `json:"connection"`
	Disposition string         `json:"disposition"`
	Correlated  bool           `json:"-"`
	Policies    []*flow.Policy `json:"policies,omitempty"`
	Src         Workload       `json:"src"`
	Dest        Workload       `json:"dest"`
	Count       int            `json:"count"`
	NodeName    string         `json:"node_name,omitempty"`
	Timestamp   time.Time      `json:"timestamp"`
}

// AggregationKey is the key used to aggregate policy action logging entry.
func (e *PolicyActionLogEntry) AggregationKey() interface{} {
	key := e.Connection
	key.SrcPort = 0
	return key
}

// SkipLogging returns wether the event should be logged.
func (e *PolicyActionLogEntry) SkipLogging(allowUncorrelated bool) bool {
	if e.Disposition == PolicyDispositionDeny {
		return false
	}

	// TODO(markstjohn): remove condition once policy correlation is supported
	// for node firewall policies.
	if e.isNodeTraffic() {
		return false
	}

	if len(e.Policies) > 0 {
		e.Correlated = true
	}
	if !e.Correlated && allowUncorrelated {
		// additionally check if the remote workloads of the entry have been populated.
		// This means the observe resolved the remote endpoint.
		if e.Connection.Direction == ConnectionDirectionIngress && e.Src.PodName != "" {
			return false
		}
		if e.Connection.Direction == ConnectionDirectionEgress && e.Dest.PodName != "" {
			return false
		}
	}

	return e.Policies == nil
}

func (e *PolicyActionLogEntry) isNodeTraffic() bool {
	return (e.Connection.Direction == ConnectionDirectionIngress && e.Dest.PodName == "") || (e.Connection.Direction == ConnectionDirectionEgress && e.Src.PodName == "")
}
