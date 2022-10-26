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
	"io/ioutil"
	"os"
	"path"
	"reflect"
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
	"github.com/cilium/cilium/pkg/testutils"
	"github.com/golang/protobuf/ptypes/timestamp"
	"github.com/google/go-cmp/cmp"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"
)

const (
	// maxRetry when verifying log content.
	maxRetry = 5

	// allowLog is the expected policy log for the allowFlow
	allowLog = `{"connection":{"src_ip":"10.84.1.7","dest_ip":"10.84.0.11","src_port":55644,"dest_port":8080,"protocol":"tcp","direction":"ingress"},"disposition":"allow","policies":[{"kind":"NetworkPolicy","name":"allow-all","namespace":"default"}],"src":{"pod_name":"client-allow-7b78d7c957-zkn54","workload_kind":"ReplicaSet","workload_name":"client-allow-7b78d7c957","pod_namespace":"default","namespace":"default"},"dest":{"pod_name":"test-service-745c798fc9-hzpxt","workload_kind":"ReplicaSet","workload_name":"test-service-745c798fc9","pod_namespace":"default","namespace":"default"},"count":1,"timestamp":"2020-06-13T21:29:31.445836587Z"}` + "\n"

	// denyLog is the expected policy log for the denyFlow
	denyLog = `{"connection":{"src_ip":"10.84.1.8","dest_ip":"10.84.0.11","src_port":45084,"dest_port":8080,"protocol":"tcp","direction":"ingress"},"disposition":"deny","src":{"pod_name":"client-deny-5689846f5b-cqqsj","workload_kind":"ReplicaSet","workload_name":"client-deny-5689846f5b","pod_namespace":"default","namespace":"default"},"dest":{"pod_name":"test-service-745c798fc9-hzpxt","workload_kind":"ReplicaSet","workload_name":"test-service-745c798fc9","pod_namespace":"default","namespace":"default"},"count":1,"timestamp":"2020-06-13T21:30:22.292379064Z"}` + "\n"
)

var (
	// configTemplate is a template for the config file.
	configTemplate = "logFilePath: %s \nlogFileName: %s\nlogFileMaxSize: 1\nlogFileMaxBackups: 1\nmaxLogRate: 200\nlogQueueSize: 100\ndenyAggregationSeconds: 2\ndenyAggregationMapSize: 100\nlogNodeName: false"

	templateCfg = policyLoggerConfig{
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

	npPolicy = &Policy{
		Kind:      "NetworkPolicy",
		Name:      "np",
		Namespace: "default",
	}

	cnpPolicy = &Policy{
		Kind:      "CiliumNetworkPolicy",
		Name:      "cnp",
		Namespace: "default",
	}

	ccnpPolicy = &Policy{
		Kind: "CiliumClusterwideNetworkPolicy",
		Name: "ccnp",
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
			Kind:      "NetworkPolicy",
			Name:      "allow-all",
			Namespace: "default",
		},
	}, nil
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

func createConfigFile(t *testing.T, fp, cfg string) {
	t.Helper()
	if _, err := os.Stat(fp); !os.IsNotExist(err) {
		os.Remove(fp)
	}

	file, err := os.OpenFile(fp, os.O_RDWR|os.O_CREATE, 0755)
	if err != nil {
		t.Fatalf("OpenFile(%v) = (_, %v), want (_, nil)", fp, err)
	}
	defer file.Close()
	_, err = file.Write([]byte(cfg))
	if err != nil {
		t.Fatalf("Write(%v) = (_, %v), want (_, nil)", cfg, err)
	}
}

func setupConfig(t *testing.T) string {
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

	configFilePath := path.Join(dir, "policy-logging.conf")
	config := fmt.Sprintf(configTemplate, dir, templateCfg.logFileName)
	createConfigFile(t, configFilePath, config)
	cfg := loadInternalConfig(configFilePath)
	refCfg := templateCfg
	refCfg.logFilePath = dir
	if !reflect.DeepEqual(*cfg, refCfg) {
		t.Fatalf("loadInternalConfig= %v, want %v", cfg, refCfg)
	}
	return configFilePath
}

// TestLogger tests the quick state changes of logging spec when flow keeps coming in.
func TestLoggerQuickStateChange(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
	configFilePath := setupConfig(t)

	dpatcher := dispatcher.NewDispatcher()
	observer := dpatcher.(dispatcher.Observer)
	logger := &networkPolicyLogger{
		dispatcher:       dpatcher,
		policyCorrelator: &testPolicyCorrelator{},
		storeGetter:      &testStoreGetter{},
		spec:             getLogSpec(nil),
		configFilePath:   configFilePath,
	}

	if err, cb := logger.Start(); err != nil {
		t.Fatalf("logger.Start() = (_, %v), want (_, nil)", err)
	} else if cb != nil {
		cb()
	}
	defer logger.Stop()

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
	fp := path.Join(logger.cfg.logFilePath, logger.cfg.logFileName)
	retryCheckFileContent(t, fp, want, maxRetry)

	// Test updating configuration to log both allowed and denied traffic.
	// Verify that both allow and deny log will not be logged.
	spec.Cluster.Allow.Log = true
	spec.Cluster.Deny.Log = true
	if update := logger.UpdateLoggingSpec(&spec); !update {
		t.Fatalf("UpdateLoggingSpec(%v) = %v, want true", spec, update)
	}
	observer.OnDecodedFlow(context.Background(), allowFlow)
	observer.OnDecodedFlow(context.Background(), denyFlow)
	want = want + allowLog + denyLog
	retryCheckFileContent(t, fp, want, maxRetry)

	spec.Cluster.Allow.Log = false
	spec.Cluster.Deny.Log = true
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

func retryCheckFileContent(t *testing.T, fp string, want string, maxRetry int) {
	t.Helper()
	check := func(path, want string) error {
		if _, err := os.Stat(fp); err != nil {
			return fmt.Errorf("fail to stat file: %v", err)
		}

		if b, err := ioutil.ReadFile(fp); err != nil {
			return fmt.Errorf("Readfile() = (_, %v), want (%s, nil)", err, want)
		} else if !reflect.DeepEqual(b, []byte(want)) {
			return fmt.Errorf("ReadFile() = (%s, nil), want (%s, nil)", string(b), want)
		}
		return nil
	}
	err := check(fp, want)
	retry := 0
	for err != nil && retry < maxRetry {
		time.Sleep(2 * time.Second)
		retry++
		err = check(fp, want)
	}
	if err != nil {
		t.Fatalf("retryCheckFileContent() = %v, want nil", err)
	}
}

// TestDenyLogAggregation tests the deny logs are correctly aggregated.
func TestDenyLogAggregation(t *testing.T) {
	t.Parallel()
	configFilePath := setupConfig(t)

	dpatcher := dispatcher.NewDispatcher()
	observer := dpatcher.(dispatcher.Observer)
	logger := &networkPolicyLogger{
		dispatcher:       dpatcher,
		policyCorrelator: &testPolicyCorrelator{},
		storeGetter:      &testStoreGetter{},
		spec:             getLogSpec(nil),
		configFilePath:   configFilePath,
	}

	if err, cb := logger.Start(); err != nil {
		t.Fatalf("logger.Start() = (_, %v), want (_, nil)", err)
	} else if cb != nil {
		cb()
	}
	defer logger.Stop()

	spec := v1alpha1.NetworkLoggingSpec{}
	spec.Cluster.Deny.Log = true
	if update := logger.UpdateLoggingSpec(&spec); !update {
		t.Fatalf("UpdateLoggingSpec(%v) = %v, want true", spec, update)
	}
	fp := path.Join(logger.cfg.logFilePath, logger.cfg.logFileName)
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
	t.Parallel()
	configFilePath := setupConfig(t)

	s := &testStoreGetter{}
	s.Init()
	dpatcher := dispatcher.NewDispatcher()
	observer := dpatcher.(dispatcher.Observer)
	logger := &networkPolicyLogger{
		dispatcher:       dpatcher,
		policyCorrelator: &testPolicyCorrelator{},
		storeGetter:      s,
		spec:             getLogSpec(nil),
		configFilePath:   configFilePath,
	}
	if err, cb := logger.Start(); err != nil {
		t.Fatalf("logger.Start() = (_, %v), want (_, nil)", err)
	} else if cb != nil {
		cb()
	}
	defer logger.Stop()

	// Setup the test k8s data store.
	policy := &slim_networkingv1.NetworkPolicy{}
	policy.ObjectMeta.Name = "allow-all"
	policy.ObjectMeta.Namespace = "default"
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
	fp := path.Join(logger.cfg.logFilePath, logger.cfg.logFileName)
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
	time.Sleep(3 * time.Second)
	retryCheckFileContent(t, fp, want, maxRetry)
}

func TestNetworkPolicyLogger_allowedPoliciesForDelegate(t *testing.T) {
	setupConfig(t)

	getter := &testStoreGetter{}
	getter.Init()
	seedStores(t, getter)

	logger := &networkPolicyLogger{
		dispatcher:  dispatcher.NewDispatcher(),
		storeGetter: getter,
		spec:        getLogSpec(nil),
	}
	logger.UpdateLoggingSpec(&v1alpha1.NetworkLoggingSpec{})

	npNotAnnotated := &Policy{
		Kind:      "NetworkPolicy",
		Name:      "not-annotated",
		Namespace: npPolicy.Namespace,
	}
	cnpNotAnnotated := &Policy{
		Kind:      "CiliumNetworkPolicy",
		Name:      "not-annotated",
		Namespace: cnpPolicy.Namespace,
	}
	ccnpNotAnnotated := &Policy{
		Kind: "CiliumClusterwideNetworkPolicy",
		Name: "not-annotated",
	}

	testCases := []struct {
		name     string
		policies []*Policy
		want     []*Policy
	}{
		{
			name: "no input policies",
		},
		{
			name:     "np",
			policies: []*Policy{npPolicy, npNotAnnotated},
			want:     []*Policy{npPolicy},
		},
		{
			name:     "cnp",
			policies: []*Policy{cnpPolicy, cnpNotAnnotated},
			want:     []*Policy{cnpPolicy},
		},
		{
			name:     "ccnp",
			policies: []*Policy{ccnpPolicy, ccnpNotAnnotated},
			want:     []*Policy{ccnpPolicy},
		},
		{
			name:     "all",
			policies: []*Policy{npPolicy, npNotAnnotated, cnpPolicy, cnpNotAnnotated, ccnpPolicy, ccnpNotAnnotated},
			want:     []*Policy{npPolicy, cnpPolicy, ccnpPolicy},
		},
	}
	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			got := logger.allowedPoliciesForDelegate(tc.policies)
			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Errorf("allowedPoliciesForDelegate(_) diff (-want +got):\n%s", diff)
			}
		})
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
