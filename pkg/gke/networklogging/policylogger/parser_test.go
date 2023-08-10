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
	"testing"

	"github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/pkg/policy/correlation"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

func TestIsNodeTraffic(t *testing.T) {
	tests := []struct {
		name  string
		entry *PolicyActionLogEntry
		want  bool
	}{
		{
			name:  "empty entry",
			entry: &PolicyActionLogEntry{},
		},
		{
			name: "pod ingress traffic",
			entry: &PolicyActionLogEntry{
				Connection: Connection{
					Direction: ConnectionDirectionIngress,
				},
				Dest: Workload{
					PodName: "pod",
				},
			},
		},
		{
			name: "pod egress traffic",
			entry: &PolicyActionLogEntry{
				Connection: Connection{
					Direction: ConnectionDirectionEgress,
				},
				Src: Workload{
					PodName: "pod",
				},
			},
		},
		{
			name: "node ingress traffic",
			entry: &PolicyActionLogEntry{
				Connection: Connection{
					Direction: ConnectionDirectionIngress,
				},
			},
			want: true,
		},
		{
			name: "node egress traffic",
			entry: &PolicyActionLogEntry{
				Connection: Connection{
					Direction: ConnectionDirectionEgress,
				},
			},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := tt.entry
			if got := e.isNodeTraffic(); got != tt.want {
				t.Errorf("isNodeTraffic() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNetworkPolicyLogger_flowToPolicyActionLogEntry(t *testing.T) {
	correlator := correlation.NewFakePolicyCorrelator(
		correlation.WithEntry("flow", correlation.NewFakePolicyCorrelatorResult()),
	)
	tests := []struct {
		name       string
		correlator correlation.Correlator
		flow       *flow.Flow
		want       *PolicyActionLogEntry
		wantErr    bool
	}{
		{
			name:       "pod-to-pod allow tcp ingress",
			correlator: correlator,
			flow: &flow.Flow{
				Uuid:             "flow",
				Verdict:          flow.Verdict_FORWARDED,
				TrafficDirection: flow.TrafficDirection_INGRESS,
				IP: &flow.IP{
					Source:      "1.1.1.1",
					Destination: "2.2.2.2",
				},
				L4: &flow.Layer4{
					Protocol: &flow.Layer4_TCP{
						TCP: &flow.TCP{
							DestinationPort: 80,
							SourcePort:      65535,
						},
					},
				},
				Source: &flow.Endpoint{
					PodName:   "src",
					Namespace: "ns",
					Workloads: []*flow.Workload{
						{Kind: "Pod", Name: "src"},
					},
				},
				Destination: &flow.Endpoint{
					PodName:   "dst",
					Namespace: "ns",
					Workloads: []*flow.Workload{
						{Kind: "Pod", Name: "dst"},
					},
				},
				NodeName: "ingress-node",
			},
			want: &PolicyActionLogEntry{
				Disposition: PolicyDispositionAllow,
				Connection: Connection{
					Direction: ConnectionDirectionIngress,
					SrcIP:     "1.1.1.1",
					DestIP:    "2.2.2.2",
					SrcPort:   65535,
					DestPort:  80,
					Protocol:  "tcp",
				},
				Src: Workload{
					PodName:      "src",
					WorkloadKind: "Pod",
					WorkloadName: "src",
					PodNamespace: "ns",
					Namespace:    "ns",
				},
				Dest: Workload{
					PodName:      "dst",
					WorkloadKind: "Pod",
					WorkloadName: "dst",
					PodNamespace: "ns",
					Namespace:    "ns",
				},
				NodeName: "ingress-node",
				Count:    1,
			},
		},
		{
			name:       "node-to-pod allow icmp egress",
			correlator: correlator,
			flow: &flow.Flow{
				Uuid:             "flow",
				Verdict:          flow.Verdict_FORWARDED,
				TrafficDirection: flow.TrafficDirection_EGRESS,
				IP: &flow.IP{
					Source:      "1.1.1.1",
					Destination: "2.2.2.2",
				},
				L4: &flow.Layer4{
					Protocol: &flow.Layer4_ICMPv4{
						ICMPv4: &flow.ICMPv4{},
					},
				},
				Source: &flow.Endpoint{},
				Destination: &flow.Endpoint{
					PodName:   "dst",
					Namespace: "ns",
					Workloads: []*flow.Workload{
						{Kind: "Pod", Name: "dst"},
					},
				},
				NodeName: "egress-node",
			},
			want: &PolicyActionLogEntry{
				Disposition: PolicyDispositionAllow,
				Connection: Connection{
					Direction: ConnectionDirectionEgress,
					SrcIP:     "1.1.1.1",
					DestIP:    "2.2.2.2",
					Protocol:  "icmp",
				},
				Src: Workload{
					NodeName:     "egress-node",
					WorkloadKind: "Node",
				},
				Dest: Workload{
					PodName:      "dst",
					WorkloadKind: "Pod",
					WorkloadName: "dst",
					PodNamespace: "ns",
					Namespace:    "ns",
				},
				NodeName: "egress-node",
				Count:    1,
			},
		},
		{
			name:       "node-to-node deny udp ingress",
			correlator: correlator,
			flow: &flow.Flow{
				Uuid:             "flow",
				Verdict:          flow.Verdict_DROPPED,
				TrafficDirection: flow.TrafficDirection_INGRESS,
				IP: &flow.IP{
					Source:      "1.1.1.1",
					Destination: "2.2.2.2",
				},
				L4: &flow.Layer4{
					Protocol: &flow.Layer4_UDP{
						UDP: &flow.UDP{
							SourcePort:      65535,
							DestinationPort: 53,
						},
					},
				},
				Source:      &flow.Endpoint{},
				Destination: &flow.Endpoint{},
				NodeName:    "ingress-node",
			},
			want: &PolicyActionLogEntry{
				Disposition: PolicyDispositionDeny,
				Connection: Connection{
					Direction: ConnectionDirectionIngress,
					SrcIP:     "1.1.1.1",
					DestIP:    "2.2.2.2",
					SrcPort:   65535,
					DestPort:  53,
					Protocol:  "udp",
				},
				Src: Workload{
					Instance: "1.1.1.1",
				},
				Dest: Workload{
					NodeName:     "ingress-node",
					WorkloadKind: "Node",
				},
				NodeName: "ingress-node",
				Count:    1,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n := &networkPolicyLogger{
				cfg: &policyLoggerConfig{
					logNodeName: true,
				},
				policyCorrelator: tt.correlator,
			}
			got, err := n.flowToPolicyActionLogEntry(tt.flow)
			if (err != nil) != tt.wantErr {
				t.Fatalf("networkPolicyLogger.flowToPolicyActionLogEntry() error = %v, wantErr %v", err, tt.wantErr)
			}
			if diff := cmp.Diff(tt.want, got, cmpopts.IgnoreFields(PolicyActionLogEntry{}, "Timestamp")); diff != "" {
				t.Errorf("networkPolicyLogger.flowToPolicyActionLogEntry() diff (-want +got):\n%s", diff)
			}
		})
	}
}
