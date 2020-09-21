package policylogger

import (
	"github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/pkg/monitor/api"
	"github.com/golang/protobuf/ptypes/timestamp"
)

const (
	// allowLog is the expected policy log for the allowFlow
	allowLog = `{"connection":{"src_ip":"10.84.1.7","dest_ip":"10.84.0.11","src_port":55644,"dest_port":8080,"protocol":"tcp","direction":"ingress"},"disposition":"allow","policies":[{"name":"allow-all","namespace":"default"}],"src":{"pod_name":"client-allow-7b78d7c957-zkn54","pod_namespace":"default"},"dest":{"pod_name":"test-service-745c798fc9-hzpxt","pod_namespace":"default"},"count":1,"timestamp":"2020-06-13T21:29:31.445836587Z"}`

	// denyLog is the expected policy log for the denyFlow
	denyLog = `{"connection":{"src_ip":"10.84.1.8","dest_ip":"10.84.0.11","src_port":45084,"dest_port":8080,"protocol":"tcp","direction":"ingress"},"disposition":"deny","src":{"pod_name":"client-deny-5689846f5b-cqqsj","pod_namespace":"default"},"dest":{"pod_name":"test-service-745c798fc9-hzpxt","pod_namespace":"default"},"count":1,"timestamp":"2020-06-13T21:30:22.292379064Z"}`

	// testCfgString is the config file content for the testCfg
	testCfgString = "logFilePath: /tmp/test \nlogFileName: policy_action.log\nlogFileMaxSize: 1\nlogFileMaxBackups: 1\nlogQueueSize: 100\ndenyAggregationSeconds: 2\ndenyAggregationMapSize: 100\nlogNodeName: false"
)

var (
	testCfg = policyLoggerConfig{
		logFilePath:            "/tmp/test",
		logFileName:            "policy_action.log",
		logFileMaxSize:         1,
		logFileMaxBackups:      1,
		maxLogRate:             defaultConfig.maxLogRate,
		logQueueSize:           100,
		denyAggregationSeconds: 2,
		denyAggregationMapSize: 100,
		logNodeName:            false,
	}

	allowFlow = &flow.Flow{
		Time:       &timestamp.Timestamp{Seconds: 1592083771, Nanos: 445836587},
		Verdict:    flow.Verdict_FORWARDED,
		DropReason: 0,
		Ethernet:   &flow.Ethernet{Source: "d2:21:68:fb:9e:68", Destination: "de:88:7b:80:52:29"},
		IP: &flow.IP{
			Source:      "10.84.1.7",
			Destination: "10.84.0.11",
			IpVersion:   flow.IPVersion_IPv4,
		},
		L4: &flow.Layer4{Protocol: &flow.Layer4_TCP{
			TCP: &flow.TCP{
				SourcePort:      55644,
				DestinationPort: 8080,
				Flags:           &flow.TCPFlags{SYN: true},
			},
		}},
		Source: &flow.Endpoint{
			Identity:  24583,
			Namespace: "default",
			Labels: []string{
				"k8s:app=client-allow",
				"k8s:io.cilium.k8s.policy.cluster=default",
				"k8s:io.cilium.k8s.policy.serviceaccount=default",
				"k8s:io.kubernetes.pod.namespace=default",
			},
			PodName: "client-allow-7b78d7c957-zkn54",
		},
		Destination: &flow.Endpoint{
			ID:        1072,
			Identity:  15292,
			Namespace: "default",
			Labels: []string{
				"k8s:app=client-allow",
				"k8s:io.cilium.k8s.policy.cluster=default",
				"k8s:io.cilium.k8s.policy.serviceaccount=default",
				"k8s:io.kubernetes.pod.namespace=default",
			},
			PodName: "test-service-745c798fc9-hzpxt",
		},
		Type:                  flow.FlowType_L3_L4,
		NodeName:              "gke-demo-default-pool-e8df3298-412p",
		Reply:                 false,
		EventType:             &flow.CiliumEventType{Type: int32(api.MessageTypePolicyVerdict)},
		TrafficDirection:      flow.TrafficDirection_INGRESS,
		PolicyMatchType:       api.PolicyMatchL3L4,
		TraceObservationPoint: flow.TraceObservationPoint_UNKNOWN_POINT,
	}

	denyFlow = &flow.Flow{
		Time:       &timestamp.Timestamp{Seconds: 1592083822, Nanos: 292379064},
		Verdict:    flow.Verdict_DROPPED,
		DropReason: 133,
		Ethernet:   &flow.Ethernet{Source: "d2:21:68:fb:9e:68", Destination: "de:88:7b:80:52:29"},
		IP: &flow.IP{
			Source:      "10.84.1.8",
			Destination: "10.84.0.11",
			IpVersion:   flow.IPVersion_IPv4,
		},
		L4: &flow.Layer4{Protocol: &flow.Layer4_TCP{
			TCP: &flow.TCP{
				SourcePort:      45084,
				DestinationPort: 8080,
				Flags:           &flow.TCPFlags{SYN: true},
			},
		}},
		Source: &flow.Endpoint{
			Identity:  24583,
			Namespace: "default",
			Labels: []string{
				"k8s:app=client-deny",
				"k8s:io.cilium.k8s.policy.cluster=default",
				"k8s:io.cilium.k8s.policy.serviceaccount=default",
				"k8s:io.kubernetes.pod.namespace=default",
			},
			PodName: "client-deny-5689846f5b-cqqsj",
		},
		Destination: &flow.Endpoint{
			ID:        1072,
			Identity:  15292,
			Namespace: "default",
			Labels: []string{
				"k8s:app=client-allow",
				"k8s:io.cilium.k8s.policy.cluster=default",
				"k8s:io.cilium.k8s.policy.serviceaccount=default",
				"k8s:io.kubernetes.pod.namespace=default",
			},
			PodName: "test-service-745c798fc9-hzpxt",
		},
		Type:                  flow.FlowType_L3_L4,
		NodeName:              "gke-demo-default-pool-e8df3298-412p",
		Reply:                 false,
		EventType:             &flow.CiliumEventType{Type: int32(api.MessageTypePolicyVerdict)},
		TrafficDirection:      flow.TrafficDirection_INGRESS,
		PolicyMatchType:       api.PolicyMatchNone,
		TraceObservationPoint: flow.TraceObservationPoint_UNKNOWN_POINT,
	}
)
