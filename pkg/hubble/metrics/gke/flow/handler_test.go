package flow

import (
	"context"
	"fmt"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/wrapperspb"

	pb "github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/pkg/hubble/metrics/api"
	monitorAPI "github.com/cilium/cilium/pkg/monitor/api"
)

const (
	destinationLabelIdx   = 0
	isReplyLabelIdx       = 1
	nodeNameLabelIdx      = 2
	portLabelIdx          = 3
	protocolLabelIdx      = 4
	sourceLabelIdx        = 5
	verdictLabelIdx       = 6
	verdictReasonLabelIdx = 7
)

func TestFlowHandler(t *testing.T) {
	t.Run("Init", func(t *testing.T) {
		initSut(t)
	})

	t.Run("Status", func(t *testing.T) {
		_, h := initSut(t)
		require.Equal(t, "destination=namespace,source=namespace", h.Status())
	})

	t.Run("ProcessFlow", func(t *testing.T) {
		registry, h := initSut(t)

		flow := &pb.Flow{
			EventType: &pb.CiliumEventType{Type: monitorAPI.MessageTypePolicyVerdict},
			L4: &pb.Layer4{
				Protocol: &pb.Layer4_TCP{
					TCP: &pb.TCP{
						DestinationPort: 8080,
						SourcePort:      31313,
					},
				},
			},
			Source:           &pb.Endpoint{Namespace: "foo"},
			Destination:      &pb.Endpoint{Namespace: "bar"},
			Verdict:          pb.Verdict_FORWARDED,
			TrafficDirection: pb.TrafficDirection_INGRESS,
			IsReply:          wrapperspb.Bool(false),
			NodeName:         "node-4-name",
		}
		h.ProcessFlow(context.TODO(), flow)

		metricFamilies, err := registry.Gather()
		require.NoError(t, err)
		require.Len(t, metricFamilies, 2)

		assert.Equal(t, "pod_flow_ingress_flows_count", *metricFamilies[1].Name)
		require.Len(t, metricFamilies[1].Metric, 1)
		metric := metricFamilies[1].Metric[0]

		assert.Equal(t, "destination", *metric.Label[destinationLabelIdx].Name)
		assert.Equal(t, "bar", *metric.Label[destinationLabelIdx].Value)

		assert.Equal(t, "is_reply", *metric.Label[isReplyLabelIdx].Name)
		assert.Equal(t, "false", *metric.Label[isReplyLabelIdx].Value)

		assert.Equal(t, "node_name", *metric.Label[nodeNameLabelIdx].Name)
		assert.Equal(t, "node-4-name", *metric.Label[nodeNameLabelIdx].Value)

		assert.Equal(t, "port", *metric.Label[portLabelIdx].Name)
		assert.Equal(t, "8080", *metric.Label[portLabelIdx].Value)

		assert.Equal(t, "protocol", *metric.Label[protocolLabelIdx].Name)
		assert.Equal(t, "TCP", *metric.Label[protocolLabelIdx].Value)

		assert.Equal(t, "source", *metric.Label[sourceLabelIdx].Name)
		assert.Equal(t, "foo", *metric.Label[sourceLabelIdx].Value)

		assert.Equal(t, "verdict", *metric.Label[verdictLabelIdx].Name)
		assert.Equal(t, "FORWARDED", *metric.Label[verdictLabelIdx].Value)

		assert.Equal(t, "verdict_reason", *metric.Label[verdictReasonLabelIdx].Name)
		assert.Equal(t, "", *metric.Label[verdictReasonLabelIdx].Value)

	})

	t.Run("ProcessUnknownDirectionFlow", func(t *testing.T) {
		registry, h := initSut(t)

		flow := &pb.Flow{
			EventType: &pb.CiliumEventType{Type: monitorAPI.MessageTypePolicyVerdict},
			L4: &pb.Layer4{
				Protocol: &pb.Layer4_TCP{
					TCP: &pb.TCP{
						DestinationPort: 48976,
						SourcePort:      8080,
					},
				},
			},
			Source:           &pb.Endpoint{Namespace: "foo"},
			Destination:      &pb.Endpoint{Namespace: "bar"},
			Verdict:          pb.Verdict_FORWARDED,
			TrafficDirection: pb.TrafficDirection_TRAFFIC_DIRECTION_UNKNOWN,
			IsReply:          wrapperspb.Bool(true),
			NodeName:         "node-4-name",
		}
		h.ProcessFlow(context.TODO(), flow)

		metricFamilies, err := registry.Gather()
		require.NoError(t, err)
		require.Len(t, metricFamilies, 1)

	})

	t.Run("ProcessReplyFlow", func(t *testing.T) {
		registry, h := initSut(t)

		flow := &pb.Flow{
			EventType: &pb.CiliumEventType{Type: monitorAPI.MessageTypePolicyVerdict},
			L4: &pb.Layer4{
				Protocol: &pb.Layer4_TCP{
					TCP: &pb.TCP{
						DestinationPort: 48976,
						SourcePort:      8080,
					},
				},
			},
			Source:           &pb.Endpoint{Namespace: "foo"},
			Destination:      &pb.Endpoint{Namespace: "bar"},
			Verdict:          pb.Verdict_FORWARDED,
			TrafficDirection: pb.TrafficDirection_INGRESS,
			IsReply:          wrapperspb.Bool(true),
			NodeName:         "node-4-name",
		}
		h.ProcessFlow(context.TODO(), flow)

		metricFamilies, err := registry.Gather()
		require.NoError(t, err)
		require.Len(t, metricFamilies, 2)

		assert.Equal(t, "pod_flow_ingress_flows_count", *metricFamilies[1].Name)
		require.Len(t, metricFamilies[1].Metric, 1)
		metric := metricFamilies[1].Metric[0]

		assert.Equal(t, "destination", *metric.Label[destinationLabelIdx].Name)
		assert.Equal(t, "bar", *metric.Label[destinationLabelIdx].Value)

		assert.Equal(t, "is_reply", *metric.Label[isReplyLabelIdx].Name)
		assert.Equal(t, "true", *metric.Label[isReplyLabelIdx].Value)

		assert.Equal(t, "node_name", *metric.Label[nodeNameLabelIdx].Name)
		assert.Equal(t, "node-4-name", *metric.Label[nodeNameLabelIdx].Value)

		assert.Equal(t, "port", *metric.Label[portLabelIdx].Name)
		assert.Equal(t, "8080", *metric.Label[portLabelIdx].Value)

		assert.Equal(t, "protocol", *metric.Label[protocolLabelIdx].Name)
		assert.Equal(t, "TCP", *metric.Label[protocolLabelIdx].Value)

		assert.Equal(t, "source", *metric.Label[sourceLabelIdx].Name)
		assert.Equal(t, "foo", *metric.Label[sourceLabelIdx].Value)

		assert.Equal(t, "verdict", *metric.Label[verdictLabelIdx].Name)
		assert.Equal(t, "FORWARDED", *metric.Label[verdictLabelIdx].Value)

		assert.Equal(t, "verdict_reason", *metric.Label[verdictReasonLabelIdx].Name)
		assert.Equal(t, "", *metric.Label[verdictReasonLabelIdx].Value)

	})

	t.Run("ProcessUnknownIsReplyFlow", func(t *testing.T) {
		registry, h := initSut(t)

		flow := &pb.Flow{
			EventType: &pb.CiliumEventType{Type: monitorAPI.MessageTypePolicyVerdict},
			L4: &pb.Layer4{
				Protocol: &pb.Layer4_TCP{
					TCP: &pb.TCP{
						DestinationPort: 28976,
						SourcePort:      8080,
					},
				},
			},
			Source:           &pb.Endpoint{Namespace: "foo"},
			Destination:      &pb.Endpoint{Namespace: "bar"},
			Verdict:          pb.Verdict_FORWARDED,
			TrafficDirection: pb.TrafficDirection_INGRESS,
		}
		h.ProcessFlow(context.TODO(), flow)

		metricFamilies, err := registry.Gather()
		require.NoError(t, err)
		require.Len(t, metricFamilies, 2)

		assert.Equal(t, "pod_flow_ingress_flows_count", *metricFamilies[1].Name)
		require.Len(t, metricFamilies[1].Metric, 1)
		metric := metricFamilies[1].Metric[0]

		assert.Equal(t, "destination", *metric.Label[destinationLabelIdx].Name)
		assert.Equal(t, "bar", *metric.Label[destinationLabelIdx].Value)

		assert.Equal(t, "is_reply", *metric.Label[isReplyLabelIdx].Name)
		assert.Equal(t, "", *metric.Label[isReplyLabelIdx].Value)

		assert.Equal(t, "node_name", *metric.Label[nodeNameLabelIdx].Name)
		assert.Equal(t, "", *metric.Label[nodeNameLabelIdx].Value)

		assert.Equal(t, "port", *metric.Label[portLabelIdx].Name)
		assert.Equal(t, "", *metric.Label[portLabelIdx].Value)

		assert.Equal(t, "protocol", *metric.Label[protocolLabelIdx].Name)
		assert.Equal(t, "TCP", *metric.Label[protocolLabelIdx].Value)

		assert.Equal(t, "source", *metric.Label[sourceLabelIdx].Name)
		assert.Equal(t, "foo", *metric.Label[sourceLabelIdx].Value)

		assert.Equal(t, "verdict", *metric.Label[verdictLabelIdx].Name)
		assert.Equal(t, "FORWARDED", *metric.Label[verdictLabelIdx].Value)

		assert.Equal(t, "verdict_reason", *metric.Label[verdictReasonLabelIdx].Name)
		assert.Equal(t, "", *metric.Label[verdictReasonLabelIdx].Value)

	})

	t.Run("ProcessDroppedFlow", func(t *testing.T) {
		registry, h := initSut(t)

		flow := &pb.Flow{
			EventType: &pb.CiliumEventType{Type: monitorAPI.MessageTypePolicyVerdict},
			L4: &pb.Layer4{
				Protocol: &pb.Layer4_TCP{
					TCP: &pb.TCP{
						DestinationPort: 8080,
						SourcePort:      31313,
					},
				},
			},
			Source:           &pb.Endpoint{Namespace: "foo"},
			Destination:      &pb.Endpoint{Namespace: "bar"},
			Verdict:          pb.Verdict_DROPPED,
			DropReasonDesc:   pb.DropReason_POLICY_DENIED,
			TrafficDirection: pb.TrafficDirection_INGRESS,
			IsReply:          wrapperspb.Bool(false),
			NodeName:         "node-4-name",
		}
		h.ProcessFlow(context.TODO(), flow)

		metricFamilies, err := registry.Gather()
		require.NoError(t, err)
		require.Len(t, metricFamilies, 2)

		assert.Equal(t, "pod_flow_ingress_flows_count", *metricFamilies[1].Name)
		require.Len(t, metricFamilies[1].Metric, 1)
		metric := metricFamilies[1].Metric[0]

		assert.Equal(t, "destination", *metric.Label[destinationLabelIdx].Name)
		assert.Equal(t, "bar", *metric.Label[destinationLabelIdx].Value)

		assert.Equal(t, "is_reply", *metric.Label[isReplyLabelIdx].Name)
		assert.Equal(t, "false", *metric.Label[isReplyLabelIdx].Value)

		assert.Equal(t, "node_name", *metric.Label[nodeNameLabelIdx].Name)
		assert.Equal(t, "node-4-name", *metric.Label[nodeNameLabelIdx].Value)

		assert.Equal(t, "port", *metric.Label[portLabelIdx].Name)
		assert.Equal(t, "8080", *metric.Label[portLabelIdx].Value)

		assert.Equal(t, "protocol", *metric.Label[protocolLabelIdx].Name)
		assert.Equal(t, "TCP", *metric.Label[protocolLabelIdx].Value)

		assert.Equal(t, "source", *metric.Label[sourceLabelIdx].Name)
		assert.Equal(t, "foo", *metric.Label[sourceLabelIdx].Value)

		assert.Equal(t, "verdict", *metric.Label[verdictLabelIdx].Name)
		assert.Equal(t, "DROPPED", *metric.Label[verdictLabelIdx].Value)

		assert.Equal(t, "verdict_reason", *metric.Label[verdictReasonLabelIdx].Name)
		assert.Equal(t, "POLICY_DENIED", *metric.Label[verdictReasonLabelIdx].Value)

	})

	t.Run("ProcessUdpFlow", func(t *testing.T) {
		registry, h := initSut(t)

		flow := &pb.Flow{
			EventType: &pb.CiliumEventType{Type: monitorAPI.MessageTypePolicyVerdict},
			L4: &pb.Layer4{
				Protocol: &pb.Layer4_UDP{
					UDP: &pb.UDP{
						DestinationPort: 8080,
						SourcePort:      31313,
					},
				},
			},
			Source:           &pb.Endpoint{Namespace: "foo"},
			Destination:      &pb.Endpoint{Namespace: "bar"},
			Verdict:          pb.Verdict_FORWARDED,
			TrafficDirection: pb.TrafficDirection_INGRESS,
			IsReply:          wrapperspb.Bool(false),
			NodeName:         "node-4-name",
		}
		h.ProcessFlow(context.TODO(), flow)

		metricFamilies, err := registry.Gather()
		require.NoError(t, err)
		require.Len(t, metricFamilies, 2)

		assert.Equal(t, "pod_flow_ingress_flows_count", *metricFamilies[1].Name)
		require.Len(t, metricFamilies[1].Metric, 1)
		metric := metricFamilies[1].Metric[0]

		assert.Equal(t, "destination", *metric.Label[destinationLabelIdx].Name)
		assert.Equal(t, "bar", *metric.Label[destinationLabelIdx].Value)

		assert.Equal(t, "is_reply", *metric.Label[isReplyLabelIdx].Name)
		assert.Equal(t, "false", *metric.Label[isReplyLabelIdx].Value)

		assert.Equal(t, "node_name", *metric.Label[nodeNameLabelIdx].Name)
		assert.Equal(t, "node-4-name", *metric.Label[nodeNameLabelIdx].Value)

		assert.Equal(t, "port", *metric.Label[portLabelIdx].Name)
		assert.Equal(t, "8080", *metric.Label[portLabelIdx].Value)

		assert.Equal(t, "protocol", *metric.Label[protocolLabelIdx].Name)
		assert.Equal(t, "UDP", *metric.Label[protocolLabelIdx].Value)

		assert.Equal(t, "source", *metric.Label[sourceLabelIdx].Name)
		assert.Equal(t, "foo", *metric.Label[sourceLabelIdx].Value)

		assert.Equal(t, "verdict", *metric.Label[verdictLabelIdx].Name)
		assert.Equal(t, "FORWARDED", *metric.Label[verdictLabelIdx].Value)

		assert.Equal(t, "verdict_reason", *metric.Label[verdictReasonLabelIdx].Name)
		assert.Equal(t, "", *metric.Label[verdictReasonLabelIdx].Value)

	})

	t.Run("ProcessIcmpFlow", func(t *testing.T) {
		registry, h := initSut(t)

		flow := &pb.Flow{
			EventType: &pb.CiliumEventType{Type: monitorAPI.MessageTypePolicyVerdict},
			L4: &pb.Layer4{
				Protocol: &pb.Layer4_ICMPv4{
					ICMPv4: &pb.ICMPv4{},
				},
			},
			Source:           &pb.Endpoint{Namespace: "foo"},
			Destination:      &pb.Endpoint{Namespace: "bar"},
			Verdict:          pb.Verdict_FORWARDED,
			TrafficDirection: pb.TrafficDirection_INGRESS,
			IsReply:          wrapperspb.Bool(false),
			NodeName:         "node-4-name",
		}
		h.ProcessFlow(context.TODO(), flow)

		metricFamilies, err := registry.Gather()
		require.NoError(t, err)
		require.Len(t, metricFamilies, 2)

		assert.Equal(t, "pod_flow_ingress_flows_count", *metricFamilies[1].Name)
		require.Len(t, metricFamilies[1].Metric, 1)
		metric := metricFamilies[1].Metric[0]

		assert.Equal(t, "destination", *metric.Label[destinationLabelIdx].Name)
		assert.Equal(t, "bar", *metric.Label[destinationLabelIdx].Value)

		assert.Equal(t, "is_reply", *metric.Label[isReplyLabelIdx].Name)
		assert.Equal(t, "false", *metric.Label[isReplyLabelIdx].Value)

		assert.Equal(t, "node_name", *metric.Label[nodeNameLabelIdx].Name)
		assert.Equal(t, "node-4-name", *metric.Label[nodeNameLabelIdx].Value)

		assert.Equal(t, "port", *metric.Label[portLabelIdx].Name)
		assert.Equal(t, "0", *metric.Label[portLabelIdx].Value)

		assert.Equal(t, "protocol", *metric.Label[protocolLabelIdx].Name)
		assert.Equal(t, "ICMPv4", *metric.Label[protocolLabelIdx].Value)

		assert.Equal(t, "source", *metric.Label[sourceLabelIdx].Name)
		assert.Equal(t, "foo", *metric.Label[sourceLabelIdx].Value)

		assert.Equal(t, "verdict", *metric.Label[verdictLabelIdx].Name)
		assert.Equal(t, "FORWARDED", *metric.Label[verdictLabelIdx].Value)

		assert.Equal(t, "verdict_reason", *metric.Label[verdictReasonLabelIdx].Name)
		assert.Equal(t, "", *metric.Label[verdictReasonLabelIdx].Value)

	})

	t.Run("ProcessFlowToEphemeralPort", func(t *testing.T) {
		registry, h := initSut(t)

		flow := &pb.Flow{
			EventType: &pb.CiliumEventType{Type: monitorAPI.MessageTypePolicyVerdict},
			L4: &pb.Layer4{
				Protocol: &pb.Layer4_TCP{
					TCP: &pb.TCP{
						DestinationPort: 48080,
						SourcePort:      31313,
					},
				},
			},
			Source:           &pb.Endpoint{Namespace: "foo"},
			Destination:      &pb.Endpoint{Namespace: "bar"},
			Verdict:          pb.Verdict_FORWARDED,
			TrafficDirection: pb.TrafficDirection_INGRESS,
			IsReply:          wrapperspb.Bool(false),
			NodeName:         "node-4-name",
		}
		h.ProcessFlow(context.TODO(), flow)

		metricFamilies, err := registry.Gather()
		require.NoError(t, err)
		require.Len(t, metricFamilies, 2)

		assert.Equal(t, "pod_flow_ingress_flows_count", *metricFamilies[1].Name)
		require.Len(t, metricFamilies[1].Metric, 1)
		metric := metricFamilies[1].Metric[0]

		assert.Equal(t, "destination", *metric.Label[destinationLabelIdx].Name)
		assert.Equal(t, "bar", *metric.Label[destinationLabelIdx].Value)

		assert.Equal(t, "is_reply", *metric.Label[isReplyLabelIdx].Name)
		assert.Equal(t, "false", *metric.Label[isReplyLabelIdx].Value)

		assert.Equal(t, "node_name", *metric.Label[nodeNameLabelIdx].Name)
		assert.Equal(t, "node-4-name", *metric.Label[nodeNameLabelIdx].Value)

		assert.Equal(t, "port", *metric.Label[portLabelIdx].Name)
		assert.Equal(t, "", *metric.Label[portLabelIdx].Value)

		assert.Equal(t, "protocol", *metric.Label[protocolLabelIdx].Name)
		assert.Equal(t, "TCP", *metric.Label[protocolLabelIdx].Value)

		assert.Equal(t, "source", *metric.Label[sourceLabelIdx].Name)
		assert.Equal(t, "foo", *metric.Label[sourceLabelIdx].Value)

		assert.Equal(t, "verdict", *metric.Label[verdictLabelIdx].Name)
		assert.Equal(t, "FORWARDED", *metric.Label[verdictLabelIdx].Value)

		assert.Equal(t, "verdict_reason", *metric.Label[verdictReasonLabelIdx].Name)
		assert.Equal(t, "", *metric.Label[verdictReasonLabelIdx].Value)

	})

	t.Run("ProcessMisbehavingFlow", func(t *testing.T) {
		registry, h := initSut(t)

		flow := &pb.Flow{
			EventType: &pb.CiliumEventType{Type: monitorAPI.MessageTypePolicyVerdict},
			L4: &pb.Layer4{
				Protocol: &pb.Layer4_TCP{
					TCP: &pb.TCP{
						DestinationPort: 8080,
						SourcePort:      31313,
					},
				},
			},
			Source:           &pb.Endpoint{Namespace: "foo"},
			Destination:      &pb.Endpoint{Namespace: "bar"},
			Verdict:          pb.Verdict_FORWARDED,
			TrafficDirection: pb.TrafficDirection_INGRESS,
			IsReply:          wrapperspb.Bool(false),
		}
		for port := 8080; port < (8080 + PerContextMetricsLimit + 100); port++ {
			flow.L4.GetTCP().DestinationPort = uint32(port)
			h.ProcessFlow(context.TODO(), flow)
		}

		metricFamilies, err := registry.Gather()
		require.NoError(t, err)
		require.Len(t, metricFamilies, 2)

		assert.Equal(t, "pod_flow_ingress_flows_count", *metricFamilies[1].Name)
		require.Len(t, metricFamilies[1].Metric, PerContextMetricsLimit)
	})

}

func BenchmarkFlowHandler(b *testing.B) {
	registry, h := initSut(b)
	flow := &pb.Flow{
		EventType: &pb.CiliumEventType{Type: monitorAPI.MessageTypePolicyVerdict},
		L4: &pb.Layer4{
			Protocol: &pb.Layer4_TCP{
				TCP: &pb.TCP{
					DestinationPort: 8080,
					SourcePort:      31313,
				},
			},
		},
		Source:           &pb.Endpoint{Namespace: "foo"},
		Destination:      &pb.Endpoint{Namespace: "bar"},
		Verdict:          pb.Verdict_FORWARDED,
		TrafficDirection: pb.TrafficDirection_INGRESS,
		IsReply:          wrapperspb.Bool(false),
	}

	// pre-populate registry
	for i := 0; i < 300; i++ {
		flow.Source.Namespace = fmt.Sprintf("foo-%d", i)
		flow.Destination.Namespace = fmt.Sprintf("bar-%d", i)
		h.ProcessFlow(context.TODO(), flow)
	}

	for i := 0; i < PerContextMetricsLimit; i++ {
		flow.L4.GetTCP().DestinationPort = uint32(8080 + i)
		h.ProcessFlow(context.TODO(), flow)
	}

	b.Run("Benchmark allowed decisions", func(b *testing.B) {

		for i := 0; i < b.N; i++ {
			flow.L4.GetTCP().DestinationPort = uint32(8080 + i%PerContextMetricsLimit)
			h.ProcessFlow(context.TODO(), flow)
		}

		metricFamilies, err := registry.Gather()
		require.NoError(b, err)
		require.Len(b, metricFamilies, 2)

		assert.Equal(b, "pod_flow_ingress_flows_count", *metricFamilies[1].Name)

	})

	b.Run("Benchmark rejected decisions", func(b *testing.B) {

		for i := 0; i < b.N; i++ {
			flow.L4.GetTCP().DestinationPort = uint32(8080 + PerContextMetricsLimit + 1)
			h.ProcessFlow(context.TODO(), flow)
		}

		metricFamilies, err := registry.Gather()
		require.NoError(b, err)
		require.Len(b, metricFamilies, 2)

		assert.Equal(b, "pod_flow_ingress_flows_count", *metricFamilies[1].Name)

	})

	b.Run("Benchmark mixed decisions", func(b *testing.B) {

		for i := 0; i < b.N; i++ {
			flow.L4.GetTCP().DestinationPort = uint32(8080 + i%(2*PerContextMetricsLimit))
			h.ProcessFlow(context.TODO(), flow)
		}

		metricFamilies, err := registry.Gather()
		require.NoError(b, err)
		require.Len(b, metricFamilies, 2)

		assert.Equal(b, "pod_flow_ingress_flows_count", *metricFamilies[1].Name)

	})
}

func initSut(t require.TestingT) (*prometheus.Registry, *flowHandler) {
	registry := prometheus.NewRegistry()
	opts := api.Options{"sourceContext": "namespace", "destinationContext": "namespace"}

	h := &flowHandler{}
	require.NoError(t, h.Init(registry, opts))

	return registry, h
}
