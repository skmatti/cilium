// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package sctp

import (
	"context"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pb "github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/pkg/hubble/metrics/api"
	monitorAPI "github.com/cilium/cilium/pkg/monitor/api"
)

func TestSctpHandlerInit(t *testing.T) {
	registry := prometheus.NewRegistry()
	opts := api.Options{"sourceContext": "namespace", "destinationContext": "namespace"}

	sctpFlowHandler := &sctpFlowHandler{}

	t.Run("Init", func(t *testing.T) {
		require.NoError(t, sctpFlowHandler.Init(registry, opts))
	})

	t.Run("Status", func(t *testing.T) {
		require.Equal(t, "destination=namespace,source=namespace", sctpFlowHandler.Status())
	})
}

func TestSctpFlowHandler(t *testing.T) {
	registry := prometheus.NewRegistry()
	opts := api.Options{"sourceContext": "namespace", "destinationContext": "namespace"}

	h := &sctpFlowHandler{}
	require.NoError(t, h.Init(registry, opts))

	t.Run("ProcessFlow", func(t *testing.T) {
		flowNotSctp := &pb.Flow{
			EventType: &pb.CiliumEventType{Type: monitorAPI.MessageTypeAccessLog},
			L7: &pb.Layer7{
				Record: &pb.Layer7_Http{Http: &pb.HTTP{}},
			},
			Source:      &pb.Endpoint{Namespace: "foo"},
			Destination: &pb.Endpoint{Namespace: "bar"},
			Verdict:     pb.Verdict_FORWARDED,
		}
		h.ProcessFlow(context.TODO(), flowNotSctp)

		metricFamilies, err := registry.Gather()
		require.NoError(t, err)
		// not an sctp flow, so should not be processed
		require.Len(t, metricFamilies, 0)

		flowSctpDropped := &pb.Flow{
			EventType: &pb.CiliumEventType{
				Type: monitorAPI.MessageTypePolicyVerdict,
			},
			L4: &pb.Layer4{
				Protocol: &pb.Layer4_SCTP{
					SCTP: &pb.SCTP{
						DestinationPort: 53,
						SourcePort:      31313,
					},
				},
			},
			Verdict: pb.Verdict_DROPPED,
		}

		h.ProcessFlow(context.TODO(), flowSctpDropped)

		metricFamilies, err = registry.Gather()
		require.NoError(t, err)
		require.Len(t, metricFamilies, 1)

		assert.Equal(t, "hubble_sctp_flows_processed_total", *metricFamilies[0].Name)
		require.Len(t, metricFamilies[0].Metric, 1)
		metric := metricFamilies[0].Metric[0]

		assert.Equal(t, "verdict", *metric.Label[2].Name)
		assert.Equal(t, "DROPPED", *metric.Label[2].Value)

		flowSctpForwarded := &pb.Flow{
			EventType: &pb.CiliumEventType{
				Type: monitorAPI.MessageTypePolicyVerdict,
			},
			L4: &pb.Layer4{
				Protocol: &pb.Layer4_SCTP{
					SCTP: &pb.SCTP{
						DestinationPort: 53,
						SourcePort:      31313,
					},
				},
			},
			Verdict: pb.Verdict_FORWARDED,
		}

		h.ProcessFlow(context.TODO(), flowSctpForwarded)

		metricFamilies, err = registry.Gather()
		require.NoError(t, err)
		require.Len(t, metricFamilies, 1)

		assert.Equal(t, "hubble_sctp_flows_processed_total", *metricFamilies[0].Name)
		require.Len(t, metricFamilies[0].Metric, 2)
		metric = metricFamilies[0].Metric[1]

		assert.Equal(t, "verdict", *metric.Label[2].Name)
		assert.Equal(t, "FORWARDED", *metric.Label[2].Value)
	})

}
