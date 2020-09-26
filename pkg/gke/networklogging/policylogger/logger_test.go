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

// +build !privileged_tests

package policylogger

import (
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/pkg/gke/apis/networklogging/v1alpha1"
	"github.com/cilium/cilium/pkg/gke/dispatcher"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_networkingv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/networking/v1"
	"github.com/cilium/cilium/pkg/monitor/api"
	"github.com/golang/protobuf/ptypes/timestamp"
	"k8s.io/client-go/tools/cache"
)

const (
	// maxRetry when verifying log content.
	maxRetry = 5

	// allowLog is the expected policy log for the allowFlow
	allowLog = `{"connection":{"src_ip":"10.84.1.7","dest_ip":"10.84.0.11","src_port":55644,"dest_port":8080,"protocol":"tcp","direction":"ingress"},"disposition":"allow","policies":[{"name":"allow-all","namespace":"default"}],"src":{"pod_name":"client-allow-7b78d7c957-zkn54","pod_namespace":"default"},"dest":{"pod_name":"test-service-745c798fc9-hzpxt","pod_namespace":"default"},"count":1,"timestamp":"2020-06-13T21:29:31.445836587Z"}`

	// denyLog is the expected policy log for the denyFlow
	denyLog = `{"connection":{"src_ip":"10.84.1.8","dest_ip":"10.84.0.11","src_port":45084,"dest_port":8080,"protocol":"tcp","direction":"ingress"},"disposition":"deny","src":{"pod_name":"client-deny-5689846f5b-cqqsj","pod_namespace":"default"},"dest":{"pod_name":"test-service-745c798fc9-hzpxt","pod_namespace":"default"},"count":1,"timestamp":"2020-06-13T21:30:22.292379064Z"}`

	// testCfgString is the config file content for the testCfg
	testCfgString = "logFilePath: /tmp/test \nlogFileName: policy_action.log\nlogFileMaxSize: 1\nlogFileMaxBackups: 1\nmaxLogRate: 200\nlogQueueSize: 100\ndenyAggregationSeconds: 2\ndenyAggregationMapSize: 100\nlogNodeName: false"
)

var (
	testCfg = policyLoggerConfig{
		logFilePath:            "/tmp/test",
		logFileName:            "policy_action.log",
		logFileMaxSize:         1,
		logFileMaxBackups:      1,
		maxLogRate:             200,
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

type testPolicyCorrelator struct{}

func (c *testPolicyCorrelator) correlatePolicy(f *flow.Flow) ([]*Policy, error) {
	if f.GetEventType().GetType() != int32(api.MessageTypePolicyVerdict) ||
		f.GetVerdict() != flow.Verdict_FORWARDED {
		return nil, nil
	}

	return []*Policy{
		{
			Name:      "allow-all",
			Namespace: "default",
		},
	}, nil
}

type testStoreGetter struct {
	policyStore    cache.Store
	namespaceStore cache.Store
}

func (c *testStoreGetter) Init() {
	c.policyStore = cache.NewStore(cache.DeletionHandlingMetaNamespaceKeyFunc)
	c.namespaceStore = cache.NewStore(cache.DeletionHandlingMetaNamespaceKeyFunc)
}

func (c *testStoreGetter) GetK8sStore(name string) cache.Store {
	if name == "networkpolicy" {
		return c.policyStore
	}
	if name == "namespace" {
		return c.namespaceStore
	}
	return nil
}

func createConfigFile(t *testing.T, cfg string) {
	if _, err := os.Stat(configFile); !os.IsNotExist(err) {
		os.Remove(configFile)
	}

	fp, err := os.OpenFile(configFile, os.O_RDWR|os.O_CREATE, 0755)
	if err != nil {
		t.Fatalf("OpenFile(%v) = (_, %v), want (_, nil)", configFile, err)
	}
	defer fp.Close()
	_, err = fp.Write([]byte(cfg))
	if err != nil {
		t.Fatalf("Write(%v) = (_, %v), want (_, nil)", cfg, err)
	}
}

func setupConfig(t *testing.T) {
	configFile = testCfg.logFilePath + "/policy-logging.conf"
	if _, err := os.Stat(testCfg.logFilePath); !os.IsNotExist(err) {
		os.RemoveAll(testCfg.logFilePath)
	}
	if err := os.MkdirAll(testCfg.logFilePath, os.ModePerm); err != nil {
		t.Fatalf("MkdirAll = %v, want nil", err)
	}
	createConfigFile(t, testCfgString)
	cfg := loadInternalConfig(configFile)
	if !reflect.DeepEqual(*cfg, testCfg) {
		t.Fatalf("loadInternalConfig= %v, want %v", cfg, testCfg)
	}
}

// TestLogger tests the quick state changes of logging spec when flow keeps coming in.
func TestLoggerQuickStateChange(t *testing.T) {
	setupConfig(t)

	dpatcher := dispatcher.NewDispatcher()
	observer := dpatcher.(dispatcher.Observer)
	logger := &networkPolicyLogger{
		dispatcher:       dpatcher,
		policyCorrelator: &testPolicyCorrelator{},
		storeGetter:      &testStoreGetter{},
		spec:             getLogSpec(nil),
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
			t.Errorf("UpdateLoggingSpec(%v) = %v, want true", spec, update)
		}
		spec.Cluster.Allow.Log = false
		if update := logger.UpdateLoggingSpec(&spec); !update {
			t.Errorf("UpdateLoggingSpec(%v) = %v, want true", spec, update)
		}
		retry++
	}
	close(stop)
	os.RemoveAll(testCfg.logFilePath)
}

// TestLogger tests the logging configuration change flow.
func TestLogger(t *testing.T) {
	setupConfig(t)

	dpatcher := dispatcher.NewDispatcher()
	observer := dpatcher.(dispatcher.Observer)
	logger := &networkPolicyLogger{
		dispatcher:       dpatcher,
		policyCorrelator: &testPolicyCorrelator{},
		storeGetter:      &testStoreGetter{},
		spec:             getLogSpec(nil),
	}

	if err, cb := logger.Start(); err != nil {
		t.Errorf("logger.Start() = (_, %v), want (_, nil)", err)
	} else if cb != nil {
		cb()
	}
	defer logger.Stop()

	// Start from log disabled with should be the default state.
	spec := v1alpha1.NetworkLoggingSpec{}
	if update := logger.UpdateLoggingSpec(&spec); update {
		t.Errorf("UpdateLoggingSpec(%v) = (%v), want false", spec, update)
	}

	// Test updating configuration to log allow traffic. Verify that deny log will not be
	// logged.
	spec.Cluster.Allow.Log = true
	if update := logger.UpdateLoggingSpec(&spec); !update {
		t.Errorf("UpdateLoggingSpec(%v) = %v, want true", spec, update)
	}
	observer.OnDecodedFlow(context.Background(), allowFlow)
	observer.OnDecodedFlow(context.Background(), denyFlow)
	want := allowLog + "\n"
	path := logger.cfg.logFilePath + "/" + logger.cfg.logFileName
	retryCheckFileContent(t, path, want, maxRetry)

	// Test updating configuration to log both allowed and denied traffic.
	// Verify that both allow and deny log will not be logged.
	spec.Cluster.Allow.Log = true
	spec.Cluster.Deny.Log = true
	if update := logger.UpdateLoggingSpec(&spec); !update {
		t.Errorf("UpdateLoggingSpec(%v) = %v, want true", spec, update)
	}
	observer.OnDecodedFlow(context.Background(), allowFlow)
	observer.OnDecodedFlow(context.Background(), denyFlow)
	want = want + allowLog + "\n" + denyLog + "\n"
	retryCheckFileContent(t, path, want, maxRetry)

	spec.Cluster.Allow.Log = false
	spec.Cluster.Deny.Log = true
	if update := logger.UpdateLoggingSpec(&spec); !update {
		t.Errorf("UpdateLoggingSpec(%v) = %v, want true", spec, update)
	}
	observer.OnDecodedFlow(context.Background(), allowFlow)
	observer.OnDecodedFlow(context.Background(), denyFlow)
	want = want + denyLog + "\n"
	retryCheckFileContent(t, path, want, maxRetry)

	if update := logger.UpdateLoggingSpec(nil); !update {
		t.Errorf("UpdateLoggingSpec(nil) = %v, want true", update)
	}
	observer.OnDecodedFlow(context.Background(), allowFlow)
	observer.OnDecodedFlow(context.Background(), denyFlow)
	retryCheckFileContent(t, path, want, maxRetry)
	os.RemoveAll(testCfg.logFilePath)
}

func retryCheckFileContent(t *testing.T, path string, want string, maxRetry int) {
	check := func(path, want string) error {
		if _, err := os.Stat(path); err != nil {
			return fmt.Errorf("fail to stat file: %v", err)
		}

		if b, err := ioutil.ReadFile(path); err != nil {
			return fmt.Errorf("Readfile() = (_, %v), want (%s, nil)", err, want)
		} else if !reflect.DeepEqual(b, []byte(want)) {
			return fmt.Errorf("ReadFile() = (%s, nil), want (%s, nil)", string(b), want)
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
		t.Errorf("retryCheckFileContent() = %v, want nil", err)
	}
}

// TestDenyLogAggregation tests the deny logs are correctly aggregated.
func TestDenyLogAggregation(t *testing.T) {
	setupConfig(t)

	dpatcher := dispatcher.NewDispatcher()
	observer := dpatcher.(dispatcher.Observer)
	logger := &networkPolicyLogger{
		dispatcher:       dpatcher,
		policyCorrelator: &testPolicyCorrelator{},
		storeGetter:      &testStoreGetter{},
		spec:             getLogSpec(nil),
	}

	if err, cb := logger.Start(); err != nil {
		t.Errorf("logger.Start() = (_, %v), want (_, nil)", err)
	} else if cb != nil {
		cb()
	}
	defer logger.Stop()

	spec := v1alpha1.NetworkLoggingSpec{}
	spec.Cluster.Deny.Log = true
	if update := logger.UpdateLoggingSpec(&spec); !update {
		t.Errorf("UpdateLoggingSpec(%v) = %v, want true", spec, update)
	}
	path := logger.cfg.logFilePath + "/" + logger.cfg.logFileName
	observer.OnDecodedFlow(context.Background(), allowFlow)
	observer.OnDecodedFlow(context.Background(), denyFlow)
	observer.OnDecodedFlow(context.Background(), denyFlow)
	observer.OnDecodedFlow(context.Background(), denyFlow)
	observer.OnDecodedFlow(context.Background(), allowFlow)
	observer.OnDecodedFlow(context.Background(), denyFlow)
	want := strings.Replace(denyLog, `"count":1`, `"count":4`, 1)
	want = want + "\n"
	retryCheckFileContent(t, path, want, maxRetry)
	os.RemoveAll(testCfg.logFilePath)
}

// TestLogDelegate tests the log delegate mode.
func TestLogDelegate(t *testing.T) {
	setupConfig(t)

	s := &testStoreGetter{}
	s.Init()
	dpatcher := dispatcher.NewDispatcher()
	observer := dpatcher.(dispatcher.Observer)
	logger := &networkPolicyLogger{
		dispatcher:       dpatcher,
		policyCorrelator: &testPolicyCorrelator{},
		storeGetter:      s,
		spec:             getLogSpec(nil),
	}
	if err, cb := logger.Start(); err != nil {
		t.Errorf("logger.Start() = (_, %v), want (_, nil)", err)
	} else if cb != nil {
		cb()
	}
	defer logger.Stop()

	// Setup the test k8s data store.
	policy := &slim_networkingv1.NetworkPolicy{}
	policy.ObjectMeta.Name = "allow-all"
	policy.ObjectMeta.Namespace = "default"
	policy.ObjectMeta.Annotations = map[string]string{AnnotationEnableAllowLogging: "true"}
	s.policyStore.Add(policy)

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
		t.Errorf("UpdateLoggingSpec(%v) =  %v, want true", spec, update)
	}
	path := logger.cfg.logFilePath + "/" + logger.cfg.logFileName
	observer.OnDecodedFlow(context.Background(), allowFlow)
	observer.OnDecodedFlow(context.Background(), denyFlow)
	want := allowLog + "\n" + denyLog + "\n"
	retryCheckFileContent(t, path, want, maxRetry)

	// Modify the annotation to false, no new log will be output now.
	policy.ObjectMeta.Annotations = map[string]string{AnnotationEnableAllowLogging: "false"}
	s.policyStore.Update(policy)
	ns.ObjectMeta.Annotations = map[string]string{AnnotationEnableDenyLogging: "false"}
	s.namespaceStore.Update(ns)
	observer.OnDecodedFlow(context.Background(), allowFlow)
	observer.OnDecodedFlow(context.Background(), denyFlow)
	// Wait to make sure that the file content is in its final state.
	time.Sleep(3 * time.Second)
	retryCheckFileContent(t, path, want, maxRetry)
	os.RemoveAll(testCfg.logFilePath)
}
