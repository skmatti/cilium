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
	"k8s.io/client-go/tools/cache"
)

const (
	// maxRetry when verifying log content.
	maxRetry = 5
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
		if err, update := logger.UpdateLoggingSpec(&spec); err != nil || !update {
			t.Errorf("UpdateLoggingSpec(%v) = (%v, %v), want (nil, false)", spec, err, update)
		}
		spec.Cluster.Allow.Log = false
		if err, update := logger.UpdateLoggingSpec(&spec); err != nil || !update {
			t.Errorf("UpdateLoggingSpec(%v) = (%v, %v), want (nil, true)", spec, err, update)
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

	// Start from log disabled with should be the default state.
	spec := v1alpha1.NetworkLoggingSpec{}
	if err, update := logger.UpdateLoggingSpec(&spec); err != nil || update {
		t.Errorf("UpdateLoggingSpec(%v) = (%v, %v), want (nil, false)", spec, err, update)
	}

	// Test updating configuration to log allow traffic. Verify that deny log will not be
	// logged.
	spec.Cluster.Allow.Log = true
	if err, update := logger.UpdateLoggingSpec(&spec); err != nil || !update {
		t.Errorf("UpdateLoggingSpec(%v) = (%v, %v), want (nil, true)", spec, err, update)
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
	if err, update := logger.UpdateLoggingSpec(&spec); err != nil || !update {
		t.Errorf("UpdateLoggingSpec(%v) = (%v, %v), want (nil, true)", spec, err, update)
	}
	observer.OnDecodedFlow(context.Background(), allowFlow)
	observer.OnDecodedFlow(context.Background(), denyFlow)
	want = want + allowLog + "\n" + denyLog + "\n"
	retryCheckFileContent(t, path, want, maxRetry)

	spec.Cluster.Allow.Log = false
	spec.Cluster.Deny.Log = true
	if err, update := logger.UpdateLoggingSpec(&spec); err != nil || !update {
		t.Errorf("UpdateLoggingSpec(%v) = (%v, %v), want (nil, true)", spec, err, update)
	}
	observer.OnDecodedFlow(context.Background(), allowFlow)
	observer.OnDecodedFlow(context.Background(), denyFlow)
	want = want + denyLog + "\n"
	retryCheckFileContent(t, path, want, maxRetry)

	if err, update := logger.UpdateLoggingSpec(nil); err != nil || !update {
		t.Errorf("UpdateLoggingSpec(nil) = (%v, %v), want (nil, true)", err, update)
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

	spec := v1alpha1.NetworkLoggingSpec{}
	spec.Cluster.Deny.Log = true
	if err, update := logger.UpdateLoggingSpec(&spec); err != nil || !update {
		t.Errorf("UpdateLoggingSpec(%v) = (%v, %v), want (nil, true)", spec, err, update)
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
	if err, update := logger.UpdateLoggingSpec(&spec); err != nil || !update {
		t.Errorf("UpdateLoggingSpec(%v) = (%v, %v), want (nil, true)", spec, err, update)
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
