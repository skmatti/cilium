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

//go:build !privileged_tests
// +build !privileged_tests

package metrics

import (
	"reflect"
	"strings"
	"testing"

	"github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/pkg/gke/dispatcher"
	"github.com/google/go-cmp/cmp"
)

const (
	srcNamespace    = "src-namespace"
	srcPodName      = "src-podname"
	srcWorkloadName = "src-workload-name"
	srcWorkloadKind = "src-workload-kind"

	destNamespace    = "dest-namespace"
	destPodName      = "dest-podname"
	destWorkloadName = "dest-workload-name"
	destWorkloadKind = "dest-workload-kind"
)

func TestIsFlowValid(t *testing.T) {
	e := &exporter{
		dispatcher: dispatcher.NewDispatcher(),
	}

	for _, tc := range []struct {
		desc   string
		flow   *flow.Flow
		ready  bool
		labels metricLabels
	}{
		{
			desc: "Invalid Flow 1: Verdict_AUDIT flow",
			flow: &flow.Flow{
				Verdict: flow.Verdict_AUDIT,
				Source: &flow.Endpoint{
					ID:        1,
					Namespace: srcNamespace,
					PodName:   srcPodName,
					Workloads: []*flow.Workload{
						{
							Name: srcWorkloadName,
							Kind: srcWorkloadKind,
						},
					},
				},
				Destination: &flow.Endpoint{
					ID:        2,
					Namespace: destNamespace,
					PodName:   destPodName,
					Workloads: []*flow.Workload{
						{
							Name: destWorkloadName,
							Kind: destWorkloadKind,
						},
					},
				},
				TrafficDirection: flow.TrafficDirection_EGRESS,
			},
			labels: metricLabels{},
			ready:  false,
		},
		{
			desc: "Invalid Flow 2: Verdict_ERROR flow",
			flow: &flow.Flow{
				Verdict: flow.Verdict_ERROR,
				Source: &flow.Endpoint{
					ID:        1,
					Namespace: srcNamespace,
					PodName:   srcPodName,
					Workloads: []*flow.Workload{
						{
							Name: srcWorkloadName,
							Kind: srcWorkloadKind,
						},
					},
				},
				Destination: &flow.Endpoint{
					ID:        2,
					Namespace: destNamespace,
					PodName:   destPodName,
					Workloads: []*flow.Workload{
						{
							Name: destWorkloadName,
							Kind: destWorkloadKind,
						},
					},
				},
				TrafficDirection: flow.TrafficDirection_EGRESS,
			},
			labels: metricLabels{},
			ready:  false,
		},
		{
			desc: "Invalid Flow 3: Verdict_VERDICT_UNKNOWN flow",
			flow: &flow.Flow{
				Verdict: flow.Verdict_VERDICT_UNKNOWN,
				Source: &flow.Endpoint{
					ID:        1,
					Namespace: srcNamespace,
					PodName:   srcPodName,
					Workloads: []*flow.Workload{
						{
							Name: srcWorkloadName,
							Kind: srcWorkloadKind,
						},
					},
				},
				Destination: &flow.Endpoint{
					ID:        2,
					Namespace: destNamespace,
					PodName:   destPodName,
					Workloads: []*flow.Workload{
						{
							Name: destWorkloadName,
							Kind: destWorkloadKind,
						},
					},
				},
				TrafficDirection: flow.TrafficDirection_EGRESS,
			},
			labels: metricLabels{},
			ready:  false,
		},
		{
			desc: "Invalid Flow 4: TrafficDirection_TRAFFIC_DIRECTION_UNKNOWN flow",
			flow: &flow.Flow{
				Verdict: flow.Verdict_FORWARDED,
				Source: &flow.Endpoint{
					ID:        1,
					Namespace: srcNamespace,
					PodName:   srcPodName,
					Workloads: []*flow.Workload{
						{
							Name: srcWorkloadName,
							Kind: srcWorkloadKind,
						},
					},
				},
				Destination: &flow.Endpoint{
					ID:        2,
					Namespace: destNamespace,
					PodName:   destPodName,
					Workloads: []*flow.Workload{
						{
							Name: destWorkloadName,
							Kind: destWorkloadKind,
						},
					},
				},
				TrafficDirection: flow.TrafficDirection_TRAFFIC_DIRECTION_UNKNOWN,
			},
			labels: metricLabels{
				verdict:   verdictLabel(flow.Verdict_FORWARDED.String()),
				direction: strings.ToLower(flow.TrafficDirection_TRAFFIC_DIRECTION_UNKNOWN.String()),
			},
			ready: false,
		},
		{
			desc: "Valid Flow 1: len(Workloads) = 0 for Destination with INGRESS flow",
			flow: &flow.Flow{
				Verdict: flow.Verdict_FORWARDED,
				Source: &flow.Endpoint{
					ID:        1,
					Namespace: srcNamespace,
					PodName:   srcPodName,
					Workloads: []*flow.Workload{
						{
							Name: srcWorkloadName,
							Kind: srcWorkloadKind,
						},
					},
				},
				Destination: &flow.Endpoint{
					ID:        2,
					Namespace: destNamespace,
					PodName:   destPodName,
					Workloads: []*flow.Workload{},
				},
				TrafficDirection: flow.TrafficDirection_INGRESS,
			},
			labels: metricLabels{
				namespace:    destNamespace,
				podName:      destPodName,
				verdict:      verdictLabel(flow.Verdict_FORWARDED.String()),
				workloadName: "",
				workloadKind: "",
				direction:    strings.ToLower(flow.TrafficDirection_INGRESS.String()),
			},
			ready: true,
		},
		{
			desc: "Valid Flow 2: len(Workloads) = 2 for Destination with INGRESS flow",
			flow: &flow.Flow{
				Verdict: flow.Verdict_FORWARDED,
				Source: &flow.Endpoint{
					ID:        1,
					Namespace: srcNamespace,
					PodName:   srcPodName,
					Workloads: []*flow.Workload{
						{
							Name: srcWorkloadName,
							Kind: srcWorkloadKind,
						},
					},
				},
				Destination: &flow.Endpoint{
					ID:        2,
					Namespace: destNamespace,
					PodName:   destPodName,
					Workloads: []*flow.Workload{
						{
							Name: "dest1-workload-name",
							Kind: "dest1-workload-kind",
						},
						{
							Name: "dest2-workload-name",
							Kind: "dest2-workload-kind",
						},
					},
				},
				TrafficDirection: flow.TrafficDirection_INGRESS,
			},
			labels: metricLabels{
				namespace:    destNamespace,
				podName:      destPodName,
				verdict:      verdictLabel(flow.Verdict_FORWARDED.String()),
				workloadName: "dest1-workload-name",
				workloadKind: "dest1-workload-kind",
				direction:    strings.ToLower(flow.TrafficDirection_INGRESS.String()),
			},
			ready: true,
		},
		{
			desc: "Valid Flow 3: len(Workloads) = 0 for Source with EGRESS flow",
			flow: &flow.Flow{
				Verdict: flow.Verdict_FORWARDED,
				Source: &flow.Endpoint{
					ID:        1,
					Namespace: srcNamespace,
					PodName:   srcPodName,
					Workloads: []*flow.Workload{},
				},
				Destination: &flow.Endpoint{
					ID:        2,
					Namespace: destNamespace,
					PodName:   destPodName,
					Workloads: []*flow.Workload{
						{
							Name: destWorkloadName,
							Kind: destWorkloadKind,
						},
					},
				},
				TrafficDirection: flow.TrafficDirection_EGRESS,
			},
			labels: metricLabels{
				namespace: srcNamespace,
				podName:   srcPodName,
				verdict:   verdictLabel(flow.Verdict_FORWARDED.String()),
				direction: strings.ToLower(flow.TrafficDirection_EGRESS.String()),
			},
			ready: true,
		},
		{
			desc: "Valid Flow 4: len(Workloads) = 2 for Source with EGRESS flow",
			flow: &flow.Flow{
				Verdict: flow.Verdict_FORWARDED,
				Source: &flow.Endpoint{
					ID:        1,
					Namespace: srcNamespace,
					PodName:   srcPodName,
					Workloads: []*flow.Workload{
						{
							Name: "src1-workload-name",
							Kind: "src1-workload-kind",
						},
						{
							Name: "src2-workload-name",
							Kind: "src2-workload-kind",
						},
					},
				},
				Destination: &flow.Endpoint{
					ID:        2,
					Namespace: destNamespace,
					PodName:   destPodName,
					Workloads: []*flow.Workload{
						{
							Name: destWorkloadName,
							Kind: destWorkloadKind,
						},
					},
				},
				TrafficDirection: flow.TrafficDirection_EGRESS,
			},
			labels: metricLabels{
				namespace:    srcNamespace,
				podName:      srcPodName,
				verdict:      verdictLabel(flow.Verdict_FORWARDED.String()),
				workloadName: "src1-workload-name",
				workloadKind: "src1-workload-kind",
				direction:    strings.ToLower(flow.TrafficDirection_EGRESS.String()),
			},
			ready: true,
		},
		{
			desc: "Valid Flow 5: Verdict_FORWARDED from Source with EGRESS flow",
			flow: &flow.Flow{
				Verdict: flow.Verdict_FORWARDED,
				Source: &flow.Endpoint{
					ID:        1,
					Namespace: srcNamespace,
					PodName:   srcPodName,
					Workloads: []*flow.Workload{
						{
							Name: srcWorkloadName,
							Kind: srcWorkloadKind,
						},
					},
				},
				Destination: &flow.Endpoint{
					ID:        2,
					Namespace: destNamespace,
					PodName:   destPodName,
					Workloads: []*flow.Workload{
						{
							Name: destWorkloadName,
							Kind: destWorkloadKind,
						},
					},
				},
				TrafficDirection: flow.TrafficDirection_EGRESS,
			},
			labels: metricLabels{
				namespace:    srcNamespace,
				podName:      srcPodName,
				verdict:      verdictLabel(flow.Verdict_FORWARDED.String()),
				workloadName: srcWorkloadName,
				workloadKind: srcWorkloadKind,
				direction:    strings.ToLower(flow.TrafficDirection_EGRESS.String()),
			},
			ready: true,
		},
		{
			desc: "Valid Flow 6: Verdict_DROPPED from Source with EGRESS flow",
			flow: &flow.Flow{
				Verdict: flow.Verdict_DROPPED,
				Source: &flow.Endpoint{
					ID:        1,
					Namespace: srcNamespace,
					PodName:   srcPodName,
					Workloads: []*flow.Workload{
						{
							Name: srcWorkloadName,
							Kind: srcWorkloadKind,
						},
					},
				},
				Destination: &flow.Endpoint{
					ID:        2,
					Namespace: destNamespace,
					PodName:   destPodName,
					Workloads: []*flow.Workload{
						{
							Name: destWorkloadName,
							Kind: destWorkloadKind,
						},
					},
				},
				TrafficDirection: flow.TrafficDirection_EGRESS,
			},
			labels: metricLabels{
				namespace:    srcNamespace,
				podName:      srcPodName,
				verdict:      verdictLabel(flow.Verdict_DROPPED.String()),
				workloadName: srcWorkloadName,
				workloadKind: srcWorkloadKind,
				direction:    strings.ToLower(flow.TrafficDirection_EGRESS.String()),
			},
			ready: true,
		},
		{
			desc: "Valid Flow 7: Verdict_FORWARDED to Destination with INGRESS flow",
			flow: &flow.Flow{
				Verdict: flow.Verdict_FORWARDED,
				Source: &flow.Endpoint{
					ID:        1,
					Namespace: srcNamespace,
					PodName:   srcPodName,
					Workloads: []*flow.Workload{
						{
							Name: srcWorkloadName,
							Kind: srcWorkloadKind,
						},
					},
				},
				Destination: &flow.Endpoint{
					ID:        2,
					Namespace: destNamespace,
					PodName:   destPodName,
					Workloads: []*flow.Workload{
						{
							Name: destWorkloadName,
							Kind: destWorkloadKind,
						},
					},
				},
				TrafficDirection: flow.TrafficDirection_INGRESS,
			},
			labels: metricLabels{
				namespace:    destNamespace,
				podName:      destPodName,
				verdict:      verdictLabel(flow.Verdict_FORWARDED.String()),
				workloadName: destWorkloadName,
				workloadKind: destWorkloadKind,
				direction:    strings.ToLower(flow.TrafficDirection_INGRESS.String()),
			},
			ready: true,
		},
		{
			desc: "Valid Flow 8: Verdict_DROPPED to Destination with INGRESS flow",
			flow: &flow.Flow{
				Verdict: flow.Verdict_DROPPED,
				Source: &flow.Endpoint{
					ID:        1,
					Namespace: srcNamespace,
					PodName:   srcPodName,
					Workloads: []*flow.Workload{
						{
							Name: srcWorkloadName,
							Kind: srcWorkloadKind,
						},
					},
				},
				Destination: &flow.Endpoint{
					ID:        2,
					Namespace: destNamespace,
					PodName:   destPodName,
					Workloads: []*flow.Workload{
						{
							Name: destWorkloadName,
							Kind: destWorkloadKind,
						},
					},
				},
				TrafficDirection: flow.TrafficDirection_INGRESS,
			},
			labels: metricLabels{
				namespace:    destNamespace,
				podName:      destPodName,
				verdict:      verdictLabel(flow.Verdict_DROPPED.String()),
				workloadName: destWorkloadName,
				workloadKind: destWorkloadKind,
				direction:    strings.ToLower(flow.TrafficDirection_INGRESS.String()),
			},
			ready: true,
		},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			labels, ready := e.isFlowValid(tc.flow)
			if got, want := ready, tc.ready; got != want {
				t.Errorf("labels.ready mismatch got = %t, want %t.", got, want)
			}
			comparer := cmp.Comparer(func(a, b metricLabels) bool {
				return reflect.DeepEqual(a, b)
			})

			if diff := cmp.Diff(tc.labels, labels, comparer); diff != "" {
				t.Errorf("Labels mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func verdictLabel(verdict string) string {
	if verdict == flow.Verdict_FORWARDED.String() {
		return "allow"
	}
	return "deny"
}
