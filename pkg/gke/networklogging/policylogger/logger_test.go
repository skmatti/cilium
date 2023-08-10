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
	"context"
	"fmt"
	"os"
	"path"
	"strings"
	"testing"
	"time"

	"github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/pkg/gke/apis/networklogging/v1alpha1"
	"github.com/cilium/cilium/pkg/gke/dispatcher"
	"github.com/cilium/cilium/pkg/k8s"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_networkingv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/networking/v1"
	v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/k8s/types"
	"github.com/cilium/cilium/pkg/monitor/api"
	policyapi "github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/pkg/policy/correlation"
	"github.com/cilium/cilium/pkg/testutils"
	"github.com/golang/protobuf/ptypes/timestamp"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"google.golang.org/protobuf/proto"
	"gopkg.in/yaml.v2"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"
)

func Ptr[T any](v T) *T {
	return &v
}

const (
	// maxRetry when verifying log content.
	maxRetry = 5

	// allowLog is the expected policy log for the allowFlow
	allowLog = `{"connection":{"src_ip":"10.84.1.7","dest_ip":"10.84.0.11","src_port":55644,"dest_port":8080,"protocol":"tcp","direction":"ingress"},"disposition":"allow","policies":[{"kind":"NetworkPolicy","name":"np","namespace":"default"}],"src":{"pod_name":"client-allow-7b78d7c957-zkn54","workload_kind":"ReplicaSet","workload_name":"client-allow-7b78d7c957","pod_namespace":"default","namespace":"default"},"dest":{"pod_name":"test-service-745c798fc9-hzpxt","workload_kind":"ReplicaSet","workload_name":"test-service-745c798fc9","pod_namespace":"default","namespace":"default"},"count":1,"timestamp":"2020-06-13T21:29:31.445836587Z"}` + "\n"

	// denyLog is the expected policy log for the denyFlow
	denyLog = `{"connection":{"src_ip":"10.84.1.8","dest_ip":"10.84.0.11","src_port":45084,"dest_port":8080,"protocol":"tcp","direction":"ingress"},"disposition":"deny","src":{"pod_name":"client-deny-5689846f5b-cqqsj","workload_kind":"ReplicaSet","workload_name":"client-deny-5689846f5b","pod_namespace":"default","namespace":"default"},"dest":{"pod_name":"test-service-745c798fc9-hzpxt","workload_kind":"ReplicaSet","workload_name":"test-service-745c798fc9","pod_namespace":"default","namespace":"default"},"count":1,"timestamp":"2020-06-13T21:30:22.292379064Z"}` + "\n"

	// nodeAllowLog is the expected policy log for the allowFlow
	nodeAllowLog = `{"connection":{"src_ip":"10.84.1.5","dest_ip":"10.128.0.9","src_port":55644,"dest_port":22,"protocol":"tcp","direction":"ingress"},"disposition":"allow","src":{"pod_name":"client-allow-7b78d7c957-zkn54","workload_kind":"ReplicaSet","workload_name":"client-allow-7b78d7c957","pod_namespace":"default","namespace":"default"},"dest":{"node_name":"gke-demo-default-pool-e8df3298-412p","workload_kind":"Node"},"count":1,"timestamp":"2020-06-13T21:31:00.000000001Z"}` + "\n"

	// nodeDenyLog is the expected policy log for the denyFlow
	nodeDenyLog = `{"connection":{"src_ip":"10.84.1.6","dest_ip":"10.128.0.9","src_port":45084,"dest_port":22,"protocol":"tcp","direction":"ingress"},"disposition":"deny","src":{"pod_name":"client-deny-5689846f5b-cqqsj","workload_kind":"ReplicaSet","workload_name":"client-deny-5689846f5b","pod_namespace":"default","namespace":"default"},"dest":{"node_name":"gke-demo-default-pool-e8df3298-412p","workload_kind":"Node"},"count":1,"timestamp":"2020-06-13T21:32:00.000000001Z"}` + "\n"

	// allowLog is the expected policy log for the allowFlow
	uncorrelatedLog = `{"connection":{"src_ip":"10.84.1.7","dest_ip":"10.84.0.11","src_port":55644,"dest_port":8080,"protocol":"tcp","direction":"ingress"},"disposition":"allow","src":{"pod_name":"client-allow-7b78d7c957-zkn54","workload_kind":"ReplicaSet","workload_name":"client-allow-7b78d7c957","pod_namespace":"default","namespace":"default"},"dest":{"pod_name":"test-service-745c798fc9-hzpxt","workload_kind":"ReplicaSet","workload_name":"test-service-745c798fc9","pod_namespace":"default","namespace":"default"},"count":1,"timestamp":"2020-06-13T21:29:31.445836587Z"}` + "\n"

	// redirectedLog is the expected policy log for the redirectedFlow
	redirectedLog = `{"src":{"namespace":"default","pod_namespace":"default","workload_name":"client-allow","pod_name":"client-allow-ffdfccbd5-d4cqp","workload_kind":"Deployment"},"dest":{"instance":"169.254.169.254"},"connection":{"direction":"egress","dest_port":53,"src_ip":"10.84.1.6","src_port":45084,"protocol":"udp","dest_ip":"169.254.169.254"},"disposition":"allow","policies":[{"kind":"FQDNNetworkPolicy","namespace":"default","name":"client-allow"}],"count":1,"timestamp":"2020-06-13T21:32:00.000000001Z"}` + "\n"

	allowUUID      = "allowFlow"
	denyUUID       = "denyFlow"
	nodeAllowUUID  = "nodeAllowFlow"
	nodeDenyUUID   = "nodeDenyFlow"
	redirectedUUID = "redirectedFlow"
)

var (
	testCfg = PolicyLoggerConfiguration{
		LogFilePath:            proto.String("/tmp/test"),
		LogFileName:            proto.String("policy_action.log"),
		LogFileMaxSize:         Ptr(uint(1)),
		LogFileMaxBackups:      Ptr(uint(1)),
		MaxLogRate:             Ptr(uint(200)),
		LogQueueSize:           Ptr(uint(200)),
		DenyAggregationSeconds: Ptr(uint(2)),
		DenyAggregationMapSize: Ptr(uint(100)),
		LogNodeName:            proto.Bool(false),
		LogUncorrelatedEntry:   proto.Bool(false),
	}

	allowFlow = &flow.Flow{
		Uuid:       allowUUID,
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
			Workloads: []*flow.Workload{
				{
					Kind: "ReplicaSet",
					Name: "client-allow-7b78d7c957",
				},
			},
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
			Workloads: []*flow.Workload{
				{
					Kind: "ReplicaSet",
					Name: "test-service-745c798fc9",
				},
			},
		},
		Type:             flow.FlowType_L3_L4,
		NodeName:         "gke-demo-default-pool-e8df3298-412p",
		Reply:            false,
		EventType:        &flow.CiliumEventType{Type: int32(api.MessageTypePolicyVerdict)},
		TrafficDirection: flow.TrafficDirection_INGRESS,
		PolicyMatchType:  api.PolicyMatchL3L4,
		CorrelatedPolicies: []*flow.Policy{
			{Kind: "NetworkPolicy", Name: "np", Namespace: "default"},
		},
		TraceObservationPoint: flow.TraceObservationPoint_UNKNOWN_POINT,
	}

	denyFlow = &flow.Flow{
		Uuid:       denyUUID,
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
			Workloads: []*flow.Workload{
				{
					Kind: "ReplicaSet",
					Name: "client-deny-5689846f5b",
				},
			},
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
			Workloads: []*flow.Workload{
				{
					Kind: "ReplicaSet",
					Name: "test-service-745c798fc9",
				},
			},
		},
		Type:                  flow.FlowType_L3_L4,
		NodeName:              "gke-demo-default-pool-e8df3298-412p",
		Reply:                 false,
		EventType:             &flow.CiliumEventType{Type: int32(api.MessageTypePolicyVerdict)},
		TrafficDirection:      flow.TrafficDirection_INGRESS,
		PolicyMatchType:       api.PolicyMatchNone,
		TraceObservationPoint: flow.TraceObservationPoint_UNKNOWN_POINT,
	}

	nodeAllowFlow = &flow.Flow{
		Uuid:       nodeAllowUUID,
		Time:       &timestamp.Timestamp{Seconds: 1592083860, Nanos: 000000001},
		Verdict:    flow.Verdict_FORWARDED,
		DropReason: 0,
		Ethernet:   &flow.Ethernet{Source: "d2:21:68:fb:9e:68", Destination: "de:88:7b:80:52:29"},
		IP: &flow.IP{
			Source:      "10.84.1.5",
			Destination: "10.128.0.9",
			IpVersion:   flow.IPVersion_IPv4,
		},
		L4: &flow.Layer4{Protocol: &flow.Layer4_TCP{
			TCP: &flow.TCP{
				SourcePort:      55644,
				DestinationPort: 22,
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
			Workloads: []*flow.Workload{
				{
					Kind: "ReplicaSet",
					Name: "client-allow-7b78d7c957",
				},
			},
		},
		Destination: &flow.Endpoint{
			ID:        1072,
			Identity:  15292,
			Namespace: "default",
			Labels: []string{
				"k8s:beta.kubernetes.io/instance-type=e2-medium",
				"k8s:beta.kubernetes.io/os=linux",
				"k8s:cloud.google.com/gke-nodepool=default-pool",
				"k8s:kubernetes.io/hostname=gke-sandbox-1666367841-default-pool-b6d87655-18rs",
				"k8s:kubernetes.io/os=linux",
				"k8s:node.kubernetes.io/instance-type=e2-medium",
			},
		},
		Type:                  flow.FlowType_L3_L4,
		NodeName:              "gke-demo-default-pool-e8df3298-412p",
		Reply:                 false,
		EventType:             &flow.CiliumEventType{Type: int32(api.MessageTypePolicyVerdict)},
		TrafficDirection:      flow.TrafficDirection_INGRESS,
		PolicyMatchType:       api.PolicyMatchL3L4,
		TraceObservationPoint: flow.TraceObservationPoint_UNKNOWN_POINT,
	}

	nodeDenyFlow = &flow.Flow{
		Uuid:       nodeDenyUUID,
		Time:       &timestamp.Timestamp{Seconds: 1592083920, Nanos: 000000001},
		Verdict:    flow.Verdict_DROPPED,
		DropReason: 133,
		Ethernet:   &flow.Ethernet{Source: "d2:21:68:fb:9e:68", Destination: "de:88:7b:80:52:29"},
		IP: &flow.IP{
			Source:      "10.84.1.6",
			Destination: "10.128.0.9",
			IpVersion:   flow.IPVersion_IPv4,
		},
		L4: &flow.Layer4{Protocol: &flow.Layer4_TCP{
			TCP: &flow.TCP{
				SourcePort:      45084,
				DestinationPort: 22,
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
			Workloads: []*flow.Workload{
				{
					Kind: "ReplicaSet",
					Name: "client-deny-5689846f5b",
				},
			},
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
		},
		Type:                  flow.FlowType_L3_L4,
		NodeName:              "gke-demo-default-pool-e8df3298-412p",
		Reply:                 false,
		EventType:             &flow.CiliumEventType{Type: int32(api.MessageTypePolicyVerdict)},
		TrafficDirection:      flow.TrafficDirection_INGRESS,
		PolicyMatchType:       api.PolicyMatchNone,
		TraceObservationPoint: flow.TraceObservationPoint_UNKNOWN_POINT,
	}

	redirectedFlow = &flow.Flow{
		Uuid:     redirectedUUID,
		Time:     &timestamp.Timestamp{Seconds: 1592083920, Nanos: 000000001},
		Verdict:  flow.Verdict_REDIRECTED,
		Ethernet: &flow.Ethernet{Source: "d2:21:68:fb:9e:68", Destination: "de:88:7b:80:52:29"},
		IP: &flow.IP{
			Source:      "10.84.1.6",
			Destination: "169.254.169.254",
			IpVersion:   flow.IPVersion_IPv4,
		},
		L4: &flow.Layer4{Protocol: &flow.Layer4_UDP{
			UDP: &flow.UDP{
				SourcePort:      45084,
				DestinationPort: 53,
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
			PodName: "client-allow-ffdfccbd5-d4cqp",
			Workloads: []*flow.Workload{
				{
					Kind: "Deployment",
					Name: "client-allow",
				},
			},
		},
		Destination: &flow.Endpoint{
			Identity: 16777217,
			Labels: []string{
				"cidr:169.254.169.254/32",
				"reserved:world",
			},
		},
		Type:             flow.FlowType_L3_L4,
		NodeName:         "gke-demo-default-pool-e8df3298-412p",
		EventType:        &flow.CiliumEventType{Type: int32(api.MessageTypePolicyVerdict)},
		TrafficDirection: flow.TrafficDirection_EGRESS,
		PolicyMatchType:  api.PolicyMatchL3L4,
		Summary:          "UDP",
	}

	npPolicy = &flow.Policy{
		Kind:      "NetworkPolicy",
		Name:      "np",
		Namespace: "default",
	}

	cnpPolicy = &flow.Policy{
		Kind:      "CiliumNetworkPolicy",
		Name:      "cnp",
		Namespace: "default",
	}

	ccnpPolicy = &flow.Policy{
		Kind: "CiliumClusterwideNetworkPolicy",
		Name: "ccnp",
	}

	fqdnPolicy = &flow.Policy{
		Kind:      "FQDNNetworkPolicy",
		Name:      "client-allow",
		Namespace: "default",
	}
)

// testCorrelator returns fake correlator instantiated with a static entry.
func testCorrelator() *correlation.FakePolicyCorrelator {
	return correlation.NewFakePolicyCorrelator(
		correlation.WithEntry(allowUUID, correlation.NewFakePolicyCorrelatorResult(
			correlation.WithPolicies(npPolicy),
		)),
		correlation.WithEntry(redirectedUUID, correlation.NewFakePolicyCorrelatorResult(
			correlation.WithPolicies(fqdnPolicy),
		)),
	)
}

type testStoreGetter struct {
	npStore        cache.Store
	cnpStore       cache.Store
	ccnpStore      cache.Store
	namespaceStore cache.Store
}

func (c *testStoreGetter) Init() {
	c.npStore = cache.NewStore(cache.DeletionHandlingMetaNamespaceKeyFunc)
	c.cnpStore = cache.NewStore(cache.DeletionHandlingMetaNamespaceKeyFunc)
	c.ccnpStore = cache.NewStore(cache.DeletionHandlingMetaNamespaceKeyFunc)
	c.namespaceStore = cache.NewStore(cache.DeletionHandlingMetaNamespaceKeyFunc)
}

func (c *testStoreGetter) GetK8sStore(name string) cache.Store {
	if name == "NetworkPolicy" {
		return c.npStore
	}
	if name == "CiliumNetworkPolicy" {
		return c.cnpStore
	}
	if name == "CiliumClusterwideNetworkPolicy" {
		return c.ccnpStore
	}
	if name == "namespace" {
		return c.namespaceStore
	}
	return nil
}

func createConfigFile(t *testing.T, fp string, cfg []byte) {
	t.Helper()
	if _, err := os.Stat(fp); !os.IsNotExist(err) {
		os.Remove(fp)
	}

	file, err := os.OpenFile(fp, os.O_RDWR|os.O_CREATE, 0755)
	if err != nil {
		t.Fatalf("OpenFile(%v) = (_, %v), want (_, nil)", fp, err)
	}
	defer file.Close()
	_, err = file.Write(cfg)
	if err != nil {
		t.Fatalf("Write(%v) = (_, %v), want (_, nil)", cfg, err)
	}
}

func setupConfig(t *testing.T, loggerConfig *PolicyLoggerConfiguration) string {
	testutils.PrivilegedTest(t)
	tmpDir, err := os.MkdirTemp(os.TempDir(), "test-")
	if err != nil {
		t.Fatalf("Cannot create temp dir %v", err)
	}
	dir := path.Join(tmpDir, t.Name())
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		os.RemoveAll(dir)
	}
	if err := os.MkdirAll(dir, os.ModePerm); err != nil {
		t.Fatalf("MkdirAll = %v, want nil", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })

	loggerConfig.LogFilePath = proto.String(dir)
	yamlData, err := yaml.Marshal(loggerConfig)
	if err != nil {
		t.Fatalf("Failed to Marshal policyLoggerConfig: %v", err)
	}

	configFilePath := path.Join(dir, "policy-logging.conf")
	createConfigFile(t, configFilePath, yamlData)
	return configFilePath
}

// TestLogger tests the quick state changes of logging spec when flow keeps coming in.
func TestLoggerQuickStateChange(t *testing.T) {
	testutils.PrivilegedTest(t)
	t.Parallel()
	cfg := testCfg
	configFilePath := setupConfig(t, &cfg)

	dpatcher := dispatcher.NewDispatcher()
	observer := dpatcher.(dispatcher.Observer)
	logger := &networkPolicyLogger{
		dispatcher:       dpatcher,
		policyCorrelator: &correlation.FakePolicyCorrelator{},
		storeGetter:      &testStoreGetter{},
		spec:             getLogSpec(nil),
		configFilePath:   configFilePath,
	}

	stop := make(chan struct{})
	go func() {
		for {
			select {
			case <-stop:
				return
			default:
				observer.OnDecodedFlow(context.Background(), allowFlow)
			}
		}
	}()

	var retry int = 0
	for retry < 20 {
		spec := v1alpha1.NetworkLoggingSpec{}
		spec.Cluster.Allow.Log = true
		if update := logger.UpdateLoggingSpec(&spec); !update {
			t.Fatalf("UpdateLoggingSpec(%v) = %v, want true", spec, update)
		}
		spec.Cluster.Allow.Log = false
		if update := logger.UpdateLoggingSpec(&spec); !update {
			t.Fatalf("UpdateLoggingSpec(%v) = %v, want true", spec, update)
		}
		retry++
	}
	close(stop)
}

// TestLogger tests the logging configuration change flow.
func TestLogger(t *testing.T) {
	testutils.PrivilegedTest(t)
	t.Parallel()
	cfg := testCfg
	configFilePath := setupConfig(t, &cfg)

	dpatcher := dispatcher.NewDispatcher()
	observer := dpatcher.(dispatcher.Observer)
	logger := &networkPolicyLogger{
		dispatcher:       dpatcher,
		policyCorrelator: testCorrelator(),
		storeGetter:      &testStoreGetter{},
		spec:             getLogSpec(nil),
		configFilePath:   configFilePath,
	}
	err, cb := logger.Start()
	if err != nil {
		t.Fatalf("Unexpected error returned by logger.Start(): %v", err)
	}
	cb()

	defer logger.Stop()
	fp := path.Join(logger.cfg.logFilePath, logger.cfg.logFileName)

	// Start from log disabled with should be the default state.
	spec := v1alpha1.NetworkLoggingSpec{}
	if update := logger.UpdateLoggingSpec(&spec); update {
		t.Fatalf("UpdateLoggingSpec(%v) = (%v), want false", spec, update)
	}

	// Test updating configuration to log allow traffic. Verify that deny log will not be
	// logged.
	spec.Cluster.Allow.Log = true
	if update := logger.UpdateLoggingSpec(&spec); !update {
		t.Fatalf("UpdateLoggingSpec(%v) = %v, want true", spec, update)
	}
	observer.OnDecodedFlow(context.Background(), allowFlow)
	observer.OnDecodedFlow(context.Background(), denyFlow)
	want := allowLog
	retryCheckFileContent(t, fp, want, maxRetry)

	// Test updating configuration to log both allowed and denied traffic.
	// Verify that both allow and deny log will not be logged.
	spec.Cluster.Deny.Log = true
	if update := logger.UpdateLoggingSpec(&spec); !update {
		t.Fatalf("UpdateLoggingSpec(%v) = %v, want true", spec, update)
	}
	observer.OnDecodedFlow(context.Background(), allowFlow)
	observer.OnDecodedFlow(context.Background(), denyFlow)
	want = want + allowLog + denyLog
	retryCheckFileContent(t, fp, want, maxRetry)

	spec.Cluster.Allow.Log = false
	if update := logger.UpdateLoggingSpec(&spec); !update {
		t.Fatalf("UpdateLoggingSpec(%v) = %v, want true", spec, update)
	}
	observer.OnDecodedFlow(context.Background(), allowFlow)
	observer.OnDecodedFlow(context.Background(), denyFlow)
	want = want + denyLog
	retryCheckFileContent(t, fp, want, maxRetry)

	if update := logger.UpdateLoggingSpec(nil); !update {
		t.Fatalf("UpdateLoggingSpec(nil) = %v, want true", update)
	}
	observer.OnDecodedFlow(context.Background(), allowFlow)
	observer.OnDecodedFlow(context.Background(), denyFlow)
	retryCheckFileContent(t, fp, want, maxRetry)
}

// TestDenyLogAggregation tests the deny logs are correctly aggregated.
func TestDenyLogAggregation(t *testing.T) {
	testutils.PrivilegedTest(t)
	t.Parallel()
	cfg := testCfg
	configFilePath := setupConfig(t, &cfg)

	dpatcher := dispatcher.NewDispatcher()
	observer := dpatcher.(dispatcher.Observer)
	logger := &networkPolicyLogger{
		dispatcher:       dpatcher,
		policyCorrelator: testCorrelator(),
		storeGetter:      &testStoreGetter{},
		spec:             getLogSpec(nil),
		configFilePath:   configFilePath,
	}
	err, cb := logger.Start()
	if err != nil {
		t.Fatalf("Unexpected error returned by logger.Start(): %v", err)
	}
	cb()
	defer logger.Stop()
	fp := path.Join(logger.cfg.logFilePath, logger.cfg.logFileName)

	spec := v1alpha1.NetworkLoggingSpec{}
	spec.Cluster.Deny.Log = true
	if update := logger.UpdateLoggingSpec(&spec); !update {
		t.Fatalf("UpdateLoggingSpec(%v) = %v, want true", spec, update)
	}
	observer.OnDecodedFlow(context.Background(), allowFlow)
	observer.OnDecodedFlow(context.Background(), denyFlow)
	observer.OnDecodedFlow(context.Background(), denyFlow)
	observer.OnDecodedFlow(context.Background(), denyFlow)
	observer.OnDecodedFlow(context.Background(), allowFlow)
	observer.OnDecodedFlow(context.Background(), denyFlow)
	want := strings.Replace(denyLog, `"count":1`, `"count":4`, 1)
	retryCheckFileContent(t, fp, want, maxRetry)
}

// TestLogDelegate tests the log delegate mode.
func TestLogDelegate(t *testing.T) {
	testutils.PrivilegedTest(t)
	t.Parallel()
	cfg := testCfg
	configFilePath := setupConfig(t, &cfg)

	s := &testStoreGetter{}
	s.Init()
	dpatcher := dispatcher.NewDispatcher()
	observer := dpatcher.(dispatcher.Observer)
	logger := &networkPolicyLogger{
		dispatcher:       dpatcher,
		policyCorrelator: testCorrelator(),
		storeGetter:      s,
		spec:             getLogSpec(nil),
		configFilePath:   configFilePath,
	}
	err, cb := logger.Start()
	if err != nil {
		t.Fatalf("Unexpected error returned by logger.Start(): %v", err)
	}
	cb()
	defer logger.Stop()
	fp := path.Join(logger.cfg.logFilePath, logger.cfg.logFileName)

	// Setup the test k8s data store.
	policy := &slim_networkingv1.NetworkPolicy{}
	policy.ObjectMeta.Name = npPolicy.Name
	policy.ObjectMeta.Namespace = npPolicy.Namespace
	policy.ObjectMeta.Annotations = map[string]string{AnnotationEnableAllowLogging: "true"}
	s.npStore.Add(policy)

	ns := &slim_corev1.Namespace{}
	ns.ObjectMeta.Name = "default"
	ns.ObjectMeta.Annotations = map[string]string{AnnotationEnableDenyLogging: "true"}
	s.namespaceStore.Add(ns)

	// Set the logger to in delegate mode
	spec := v1alpha1.NetworkLoggingSpec{}
	spec.Cluster.Allow.Log = true
	spec.Cluster.Allow.Delegate = true
	spec.Cluster.Deny.Log = true
	spec.Cluster.Deny.Delegate = true
	if update := logger.UpdateLoggingSpec(&spec); !update {
		t.Fatalf("UpdateLoggingSpec(%v) =  %v, want true", spec, update)
	}
	observer.OnDecodedFlow(context.Background(), allowFlow)
	observer.OnDecodedFlow(context.Background(), denyFlow)
	want := allowLog + denyLog
	retryCheckFileContent(t, fp, want, maxRetry)

	// Modify the annotation to false, no new log will be output now.
	policy.ObjectMeta.Annotations = map[string]string{AnnotationEnableAllowLogging: "false"}
	s.npStore.Update(policy)
	ns.ObjectMeta.Annotations = map[string]string{AnnotationEnableDenyLogging: "false"}
	s.namespaceStore.Update(ns)
	observer.OnDecodedFlow(context.Background(), allowFlow)
	observer.OnDecodedFlow(context.Background(), denyFlow)
	// Wait to make sure that the file content is in its final state.
	retryCheckFileContent(t, fp, want, maxRetry)
}

func TestNetworkPolicyLogger_allowedPoliciesForDelegate(t *testing.T) {
	testutils.PrivilegedTest(t)
	t.Parallel()
	cfg := testCfg
	configFilePath := setupConfig(t, &cfg)

	getter := &testStoreGetter{}
	getter.Init()
	seedStores(t, getter)

	logger := &networkPolicyLogger{
		dispatcher:     dispatcher.NewDispatcher(),
		storeGetter:    getter,
		spec:           getLogSpec(nil),
		configFilePath: configFilePath,
	}
	logger.UpdateLoggingSpec(&v1alpha1.NetworkLoggingSpec{})

	npNotAnnotated := &flow.Policy{
		Kind:      "NetworkPolicy",
		Name:      "not-annotated",
		Namespace: npPolicy.Namespace,
	}
	cnpNotAnnotated := &flow.Policy{
		Kind:      "CiliumNetworkPolicy",
		Name:      "not-annotated",
		Namespace: cnpPolicy.Namespace,
	}
	ccnpNotAnnotated := &flow.Policy{
		Kind: "CiliumClusterwideNetworkPolicy",
		Name: "not-annotated",
	}

	testCases := []struct {
		name     string
		policies []*flow.Policy
		want     []*flow.Policy
	}{
		{
			name: "no input policies",
		},
		{
			name:     "np",
			policies: []*flow.Policy{npPolicy, npNotAnnotated},
			want:     []*flow.Policy{npPolicy},
		},
		{
			name:     "cnp",
			policies: []*flow.Policy{cnpPolicy, cnpNotAnnotated},
			want:     []*flow.Policy{cnpPolicy},
		},
		{
			name:     "ccnp",
			policies: []*flow.Policy{ccnpPolicy, ccnpNotAnnotated},
			want:     []*flow.Policy{ccnpPolicy},
		},
		{
			name:     "all",
			policies: []*flow.Policy{npPolicy, npNotAnnotated, cnpPolicy, cnpNotAnnotated, ccnpPolicy, ccnpNotAnnotated},
			want:     []*flow.Policy{npPolicy, cnpPolicy, ccnpPolicy},
		},
	}
	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			got := logger.allowedPoliciesForDelegate(tc.policies)
			if diff := cmp.Diff(tc.want, got, cmpopts.IgnoreUnexported(flow.Policy{})); diff != "" {
				t.Errorf("allowedPoliciesForDelegate(_) diff (-want +got):\n%s", diff)
			}
		})
	}
}

func TestNetworkPolicyLogger_NodeTraffic(t *testing.T) {
	testutils.PrivilegedTest(t)
	t.Parallel()
	cfg := testCfg
	configFilePath := setupConfig(t, &cfg)

	s := &testStoreGetter{}
	s.Init()
	ctx := context.Background()
	dpatcher := dispatcher.NewDispatcher()
	observer := dpatcher.(dispatcher.Observer)
	logger := &networkPolicyLogger{
		dispatcher:       dpatcher,
		policyCorrelator: testCorrelator(),
		storeGetter:      s,
		spec:             getLogSpec(nil),
		configFilePath:   configFilePath,
	}
	err, cb := logger.Start()
	if err != nil {
		t.Fatalf("Unexpected error returned by logger.Start(): %v", err)
	}
	cb()
	defer logger.Stop()

	// Setup the test k8s data store.
	policy := &v2.CiliumClusterwideNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name: ccnpPolicy.Name,
		},
		Spec: &policyapi.Rule{
			NodeSelector: policyapi.EndpointSelector{},
			Ingress: []policyapi.IngressRule{
				{
					IngressCommonRule: policyapi.IngressCommonRule{
						FromEntities: []policyapi.Entity{"all"},
					},
				},
			},
		},
	}
	s.npStore.Add(policy)

	// Set the logger to in delegate mode
	spec := v1alpha1.NetworkLoggingSpec{
		Node: v1alpha1.NodeLogSpec{
			Allow: v1alpha1.LogAction{
				Log: true,
			},
			Deny: v1alpha1.LogAction{
				Log: true,
			},
		},
	}
	if update := logger.UpdateLoggingSpec(&spec); !update {
		t.Errorf("UpdateLoggingSpec(%v) =  %v, want true", spec, update)
	}

	observer.OnDecodedFlow(ctx, nodeAllowFlow)
	observer.OnDecodedFlow(ctx, nodeDenyFlow)
	want := nodeAllowLog + nodeDenyLog
	fp := path.Join(logger.cfg.logFilePath, logger.cfg.logFileName)
	retryCheckFileContent(t, fp, want, maxRetry)
}

func TestNetworkPolicyLogger_DontLogDisabledTraffic(t *testing.T) {
	testutils.PrivilegedTest(t)
	t.Parallel()
	cfg := testCfg
	configFilePath := setupConfig(t, &cfg)

	s := &testStoreGetter{}
	s.Init()
	ctx := context.Background()
	dpatcher := dispatcher.NewDispatcher()
	observer := dpatcher.(dispatcher.Observer)
	logger := &networkPolicyLogger{
		dispatcher:       dpatcher,
		policyCorrelator: testCorrelator(),
		storeGetter:      s,
		spec:             getLogSpec(nil),
		configFilePath:   configFilePath,
	}
	err, cb := logger.Start()
	if err != nil {
		t.Fatalf("Unexpected error returned by logger.Start(): %v", err)
	}
	cb()
	defer logger.Stop()

	// Setup the test k8s data store.
	policy := &v2.CiliumClusterwideNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name: ccnpPolicy.Name,
		},
		Spec: &policyapi.Rule{
			NodeSelector: policyapi.EndpointSelector{},
			Ingress: []policyapi.IngressRule{
				{
					IngressCommonRule: policyapi.IngressCommonRule{
						FromEntities: []policyapi.Entity{"all"},
					},
				},
			},
		},
	}
	s.npStore.Add(policy)

	// Set the logger to in delegate mode
	spec := v1alpha1.NetworkLoggingSpec{
		Cluster: v1alpha1.ClusterLogSpec{
			Allow: v1alpha1.LogAction{
				Log: true,
			},
			Deny: v1alpha1.LogAction{
				Log: true,
			},
		},
	}
	if update := logger.UpdateLoggingSpec(&spec); !update {
		t.Fatalf("UpdateLoggingSpec(%v) =  %v, want true", spec, update)
	}

	observer.OnDecodedFlow(ctx, nodeAllowFlow)
	observer.OnDecodedFlow(ctx, nodeDenyFlow)
	fp := path.Join(logger.cfg.logFilePath, logger.cfg.logFileName)
	retryCheckFileContent(t, fp, "", maxRetry)

	observer.OnDecodedFlow(ctx, allowFlow)
	observer.OnDecodedFlow(ctx, denyFlow)
	want := allowLog + denyLog
	retryCheckFileContent(t, fp, want, maxRetry)

	if update := logger.UpdateLoggingSpec(
		&v1alpha1.NetworkLoggingSpec{
			Node: v1alpha1.NodeLogSpec{
				Allow: v1alpha1.LogAction{
					Log: true,
				},
				Deny: v1alpha1.LogAction{
					Log: true,
				},
			},
		},
	); !update {
		t.Fatalf("UpdateLoggingSpec(%v) =  %v, want true", spec, update)
	}

	observer.OnDecodedFlow(ctx, allowFlow)
	observer.OnDecodedFlow(ctx, denyFlow)
	retryCheckFileContent(t, fp, want, maxRetry)

	observer.OnDecodedFlow(ctx, nodeAllowFlow)
	observer.OnDecodedFlow(ctx, nodeDenyFlow)
	want = want + nodeAllowLog + nodeDenyLog
	retryCheckFileContent(t, fp, want, maxRetry)
}

func retryCheckFileContent(t *testing.T, path string, want string, maxRetry int) {
	t.Helper()
	check := func(path, want string) error {
		if _, err := os.Stat(path); err != nil {
			return fmt.Errorf("fail to stat file: %v", err)
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("Readfile() returned err=%v, want nil", err)
		}

		if diff := cmp.Diff(want, string(b)); diff != "" {
			return fmt.Errorf("ReadFile() string diff (-want +got):\n%s", diff)
		}
		return nil
	}
	err := check(path, want)
	retry := 0
	for err != nil && retry < maxRetry {
		time.Sleep(2 * time.Second)
		retry++
		err = check(path, want)
	}
	if err != nil {
		t.Error(err)
	}
}

func seedStores(t testing.TB, getter *testStoreGetter) {
	if err := getter.npStore.Add(&slim_networkingv1.NetworkPolicy{
		ObjectMeta: v1.ObjectMeta{
			Name:      npPolicy.Name,
			Namespace: npPolicy.Namespace,
			Annotations: map[string]string{
				AnnotationEnableAllowLogging: "true",
			},
		},
	}); err != nil {
		t.Fatalf("Unable to initialize network policy store: %v", err)
	}

	if err := getter.npStore.Add(&slim_networkingv1.NetworkPolicy{
		ObjectMeta: v1.ObjectMeta{
			Name:      "not-annotated",
			Namespace: npPolicy.Namespace,
		},
	}); err != nil {
		t.Fatalf("Unable to initialize network policy store: %v", err)
	}

	if err := getter.cnpStore.Add(&types.SlimCNP{
		CiliumNetworkPolicy: &v2.CiliumNetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      cnpPolicy.Name,
				Namespace: cnpPolicy.Namespace,
				Annotations: map[string]string{
					AnnotationEnableAllowLogging: "true",
				},
			},
		},
	}); err != nil {
		t.Fatalf("Unable to initialize network policy store: %v", err)
	}

	if err := getter.cnpStore.Add(&types.SlimCNP{
		CiliumNetworkPolicy: &v2.CiliumNetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "not-annotated",
				Namespace: cnpPolicy.Namespace,
			},
		},
	}); err != nil {
		t.Fatalf("Unable to initialize network policy store: %v", err)
	}

	if err := getter.ccnpStore.Add(k8s.ConvertToCCNP(&v2.CiliumClusterwideNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name: ccnpPolicy.Name,
			Annotations: map[string]string{
				AnnotationEnableAllowLogging: "true",
			},
		},
	})); err != nil {
		t.Fatalf("Unable to initialize network policy store: %v", err)
	}

	if err := getter.ccnpStore.Add(k8s.ConvertToCCNP(&v2.CiliumClusterwideNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name: "not-annotated",
		},
	})); err != nil {
		t.Fatalf("Unable to initialize network policy store: %v", err)
	}
}

func TestLogger_LogUncorrelatedEntries(t *testing.T) {
	testutils.PrivilegedTest(t)
	t.Parallel()
	cfg := testCfg
	cfg.LogUncorrelatedEntry = proto.Bool(true)
	configFilePath := setupConfig(t, &cfg)

	dpatcher := dispatcher.NewDispatcher()
	observer := dpatcher.(dispatcher.Observer)
	logger := &networkPolicyLogger{
		dispatcher: dpatcher,
		policyCorrelator: correlation.NewFakePolicyCorrelator(
			correlation.WithEntry(allowUUID, correlation.NewFakePolicyCorrelatorResult()),
		),
		storeGetter:    &testStoreGetter{},
		spec:           getLogSpec(nil),
		configFilePath: configFilePath,
	}
	err, cb := logger.Start()
	if err != nil {
		t.Fatalf("Unexpected error returned by logger.Start(): %v", err)
	}
	cb()

	defer logger.Stop()
	fp := path.Join(logger.cfg.logFilePath, logger.cfg.logFileName)

	// Start from log disabled with should be the default state.
	spec := v1alpha1.NetworkLoggingSpec{
		Cluster: v1alpha1.ClusterLogSpec{Allow: v1alpha1.LogAction{Log: true}},
		Node:    v1alpha1.NodeLogSpec{Allow: v1alpha1.LogAction{Log: true}},
	}
	logger.UpdateLoggingSpec(&spec)

	observer.OnDecodedFlow(context.Background(), allowFlow)
	want := uncorrelatedLog
	retryCheckFileContent(t, fp, want, maxRetry)
}

func TestLogger_DontLogUncorrelatedEntries(t *testing.T) {
	testutils.PrivilegedTest(t)
	cfg := testCfg
	configFilePath := setupConfig(t, &cfg)

	dpatcher := dispatcher.NewDispatcher()
	observer := dpatcher.(dispatcher.Observer)
	logger := &networkPolicyLogger{
		dispatcher:       dpatcher,
		policyCorrelator: testCorrelator(),
		storeGetter:      &testStoreGetter{},
		spec:             getLogSpec(nil),
		configFilePath:   configFilePath,
	}
	err, cb := logger.Start()
	if err != nil {
		t.Fatalf("Unexpected error returned by logger.Start(): %v", err)
	}
	cb()

	defer logger.Stop()
	fp := path.Join(logger.cfg.logFilePath, logger.cfg.logFileName)

	// Start from log disabled with should be the default state.
	spec := v1alpha1.NetworkLoggingSpec{
		Cluster: v1alpha1.ClusterLogSpec{Allow: v1alpha1.LogAction{Log: true}},
		Node:    v1alpha1.NodeLogSpec{Allow: v1alpha1.LogAction{Log: true}},
	}
	logger.UpdateLoggingSpec(&spec)

	observer.OnDecodedFlow(context.Background(), allowFlow)
	retryCheckFileContent(t, fp, "", maxRetry)
}

func TestLogger_HubbleCorrelationEnabled(t *testing.T) {
	testutils.PrivilegedTest(t)
	cfg := testCfg
	configFilePath := setupConfig(t, &cfg)

	dpatcher := dispatcher.NewDispatcher()
	observer := dpatcher.(dispatcher.Observer)
	logger := &networkPolicyLogger{
		dispatcher: dpatcher,
		// Noop correlator signals that the correlated policies are inherited from the flow.
		policyCorrelator:        &correlation.NoopCorrelator,
		storeGetter:             &testStoreGetter{},
		spec:                    getLogSpec(nil),
		configFilePath:          configFilePath,
		hubblePolicyCorrelation: true,
	}
	err, cb := logger.Start()
	if err != nil {
		t.Fatalf("Unexpected error returned by logger.Start(): %v", err)
	}
	cb()

	defer logger.Stop()
	fp := path.Join(logger.cfg.logFilePath, logger.cfg.logFileName)

	spec := v1alpha1.NetworkLoggingSpec{
		Cluster: v1alpha1.ClusterLogSpec{Allow: v1alpha1.LogAction{Log: true}},
		Node:    v1alpha1.NodeLogSpec{Allow: v1alpha1.LogAction{Log: true}},
	}
	logger.UpdateLoggingSpec(&spec)

	observer.OnDecodedFlow(context.Background(), allowFlow)
	retryCheckFileContent(t, fp, allowLog, maxRetry)
}
