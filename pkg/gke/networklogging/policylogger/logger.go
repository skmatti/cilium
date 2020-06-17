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

// This file holds the control logic of network policy logger.
package policylogger

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/pkg/gke/apis/networklogging/v1alpha1"
	"github.com/cilium/cilium/pkg/gke/dispatcher"
	"github.com/cilium/cilium/pkg/gke/util/aggregator"
	"github.com/cilium/cilium/pkg/gke/util/ratelimiter"
	"github.com/cilium/cilium/pkg/gke/util/writer"
	"github.com/cilium/cilium/pkg/hubble/parser/getters"
	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/monitor/api"
	"github.com/sirupsen/logrus"
)

const (
	// AnnotationEnableAllowLogging is the annotation used to enable allow logging for a network
	// policy object in allow delegate mode.
	AnnotationEnableAllowLogging = "policy.network.gke.io/enable-logging"
	// AnnotationEnableDenyLogging is the annotation used to enable deny logging for a namespace
	// in deny delegate mode.
	AnnotationEnableDenyLogging = "policy.network.gke.io/enable-deny-logging"
)

type logKey struct {
	node  bool
	allow bool
}
type logAction struct {
	log      bool
	delegate bool
}

// logSpec is a parsed result of user configuration v1alpha1.NetworkLoggingSpec
type logSpec struct {
	// log indicate whether we need to log anything at all.
	log bool
	// actions stores the detailed log actions for different scenarios.
	actions map[logKey]logAction
}

// networkPolicyLogger is the structure for network policy action logging.
type networkPolicyLogger struct {
	dispatcher       dispatcher.Dispatcher
	policyCorrelator policyCorrelator
	storeGetter      getters.StoreGetter
	flowCh           chan *flow.Flow
	stopCh           chan struct{}
	doneCh           chan struct{}
	writer           writer.Writer
	rateLimiter      *ratelimiter.RateLimiter
	aggregator       *aggregator.Aggregator
	aggregatorCh     chan *aggregator.AggregatorEntry
	counter          counters
	metricsCollector *metricsCollector
	cfg              *policyLoggerConfig

	lock lock.Mutex
	spec *logSpec
}

// getLogSpec converts the v1alpha1.NetworkLoggingSpec to logSpec.
func getLogSpec(spec *v1alpha1.NetworkLoggingSpec) *logSpec {
	if spec == nil {
		spec = &v1alpha1.NetworkLoggingSpec{}
	}
	return &logSpec{
		log: spec.Cluster.Allow.Log || spec.Cluster.Deny.Log || spec.Node.Allow.Log || spec.Node.Deny.Log,
		actions: map[logKey]logAction{
			{node: false, allow: true}:  {log: spec.Cluster.Allow.Log, delegate: spec.Cluster.Allow.Delegate},
			{node: false, allow: false}: {log: spec.Cluster.Deny.Log, delegate: spec.Cluster.Deny.Delegate},
			{node: true, allow: true}:   {log: spec.Node.Allow.Log, delegate: spec.Node.Allow.Delegate},
			{node: true, allow: false}:  {log: spec.Node.Deny.Log, delegate: spec.Node.Deny.Delegate},
		},
	}
}

func (s *logSpec) getLogAction(node, allow bool) logAction {
	return s.actions[logKey{node: node, allow: allow}]
}

// getCfg gets the current network policy logging spec.
func (n *networkPolicyLogger) getSpec() *logSpec {
	n.lock.Lock()
	defer n.lock.Unlock()
	return n.spec
}

// setCfg sets the current network policy logging spec.
func (n *networkPolicyLogger) setSpec(spec *logSpec) {
	n.lock.Lock()
	defer n.lock.Unlock()
	n.spec = spec
}

// API Interface to satisfy the Logger interface.
// UpdateLoggingSpec updates the network logging spec. Return error message if any and whether the
// configuration is updated.
func (n *networkPolicyLogger) UpdateLoggingSpec(spec *v1alpha1.NetworkLoggingSpec) (error, bool) {
	curr := getLogSpec(spec)
	old := n.getSpec()
	if reflect.DeepEqual(curr, old) {
		return nil, false
	}
	log.WithFields(logrus.Fields{"old": old, "curr": curr}).Info("Update logging spec")
	n.setSpec(curr)
	if !old.log && curr.log {
		log.Info("Start policy logger")
		if err := n.start(); err != nil {
			n.setSpec(old)
			return err, false
		}
	} else if old.log && !curr.log {
		log.Info("Stop policy logger")
		n.stop()
	}
	return nil, true
}

// start starts network policy logger.
func (n *networkPolicyLogger) start() error {
	n.cfg = loadInternalConfig(configFile)
	w, err := writer.NewFileWriter(n.cfg.logFilePath, n.cfg.logFileName,
		int(n.cfg.logFileMaxSize), int(n.cfg.logFileMaxBackups))
	if err != nil {
		log.Errorf("Fail to create new file writer %v", err)
		return fmt.Errorf("Fail to create new file writer %v", err)
	}
	n.writer = w

	// To make things simple and easy, by default no burst is allowed, so policyActionLogRate is both
	// the rate and burst for generating the rate limiter.
	n.rateLimiter = ratelimiter.NewRateLimiter(n.cfg.maxLogRate, n.cfg.maxLogRate, time.Second)
	n.rateLimiter.Start()

	n.flowCh = make(chan *flow.Flow, n.cfg.logQueueSize)
	n.stopCh = make(chan struct{})
	n.doneCh = make(chan struct{})

	if n.cfg.denyAggregationSeconds > 0 {
		n.aggregatorCh = make(chan *aggregator.AggregatorEntry, n.cfg.logQueueSize)
		n.aggregator = aggregator.NewAggregator(time.Duration(n.cfg.denyAggregationSeconds)*time.Second,
			time.Second, int(n.cfg.denyAggregationMapSize), n.aggregatorCh)
		n.aggregator.Start()
	}

	go n.run()

	if err := n.dispatcher.AddFlowListener("policy", int32(api.MessageTypePolicyVerdict), n.flowCh); err != nil {
		log.Errorf("Fail to add policy verdict listener: %v", err)
		n.stop()
		return fmt.Errorf("Fail to add policy verdict listener: %v", err)
	}
	return nil
}

// stop stops network policy logger.
func (n *networkPolicyLogger) stop() {
	close(n.stopCh)
	<-n.doneCh
}

// run listens and process the flow.
func (n *networkPolicyLogger) run() {
	log.Infof("Logger started with cfg: %s", n.cfg.print())
	ticker := time.NewTicker(time.Duration(n.cfg.counterLogInterval) * time.Second)
	prev := n.counter
	start := time.Now()
	for {
		select {
		case f := <-n.flowCh:
			n.processFlow(f)
		case ae := <-n.aggregatorCh:
			n.processAggregatedEntry(ae)
		case <-ticker.C:
			curr := &n.counter
			end := time.Now()
			diff := curr.sub(&prev)
			msg := diff.formatMsg(n.cfg.counterLogErrorOnly)
			if len(msg) > 0 {
				log.WithFields(logrus.Fields{"start": start, "end": end}).Infof("Counter changed: %s", strings.Join(msg, ", "))
			}
			prev = *curr
			start = end
		case <-n.stopCh:
			log.Info("Remove flow listener")
			n.dispatcher.RemoveFlowListener("policy", int32(api.MessageTypePolicyVerdict))
			ticker.Stop()
			n.flowCh = nil
			n.writer.Close()
			n.rateLimiter.Stop()
			if n.aggregator != nil {
				n.aggregator.Stop()
				n.aggregator = nil
			}
			close(n.doneCh)
			return
		}
	}
}

func (n *networkPolicyLogger) loggingPolicies(policies []*Policy) []*Policy {
	policyStore := n.storeGetter.GetK8sStore("networkpolicy")
	if policyStore == nil {
		log.Error("Cannot find the policy store")
		(&n.counter.storeErrors).inc(1)
		return policies
	}
	var ret []*Policy
	for _, p := range policies {
		key := p.Namespace + "/" + p.Name
		obj, exist, err := policyStore.GetByKey(key)
		if err != nil {
			log.Errorf("Fail to fetch policy object: %v", err)
			(&n.counter.storeErrors).inc(1)
			continue
		}
		// Maybe the policy is already deleted.
		if !exist {
			(&n.counter.storeErrors).inc(1)
			continue
		}
		policy := k8s.ObjToV1NetworkPolicy(obj)
		if policy.Annotations[AnnotationEnableAllowLogging] == "true" {
			ret = append(ret, p)
		}
	}
	return ret
}

func (n *networkPolicyLogger) shouldLogNamespace(name string) bool {
	namespaceStore := n.storeGetter.GetK8sStore("namespace")
	if namespaceStore == nil {
		log.Error("Cannot find the namespace store")
		(&n.counter.storeErrors).inc(1)
		return false
	}
	obj, exist, err := namespaceStore.GetByKey(name)
	if err != nil {
		log.Errorf("Fail to fetch namespace object: %v", err)
		(&n.counter.storeErrors).inc(1)
		return false
	}
	// Maybe the namespace is already deleted.
	if !exist {
		return false
	}
	namespace := k8s.ObjToV1Namespace(obj)
	if namespace.Annotations[AnnotationEnableDenyLogging] == "true" {
		return true
	}
	return false
}

func (n *networkPolicyLogger) processFlow(f *flow.Flow) {
	e, err := n.flowToPolicyActionLogEntry(f)
	if err != nil {
		(&n.counter.flowParseFails).inc(1)
		log.Debugf("Flow parsing failed: flow %v, err: %v", f, err)
		return
	}
	// Don't count the connections allowed by default, such as health checks.
	allow := isAllow(f)
	if allow && e.Policies == nil {
		log.Debugf("No log as matched policy is empty. flow: %v", f)
		return
	}

	if allow {
		(&n.counter.allowedConnections).inc(1)
	} else {
		(&n.counter.deniedConnections).inc(1)
	}

	spec := n.getSpec()

	// Only support cluster-level policy logs now. When node network policies
	// are supported, this needs to be revised.
	action := spec.getLogAction(false, allow)
	if !action.log {
		log.Debugf("Logging is disabled for cluster, allow %v", allow)
		return
	}

	if action.delegate {
		if allow {
			logPolicies := n.loggingPolicies(e.Policies)
			if len(logPolicies) == 0 {
				log.Debugf("No log for policies %v", e.Policies)
				return
			}
			e.Policies = logPolicies
		} else {
			var namespace string
			if e.Connection.Direction == ConnectionDirectionIngress {
				namespace = e.Dest.PodNamespace
			} else {
				namespace = e.Src.PodNamespace
			}
			if !n.shouldLogNamespace(namespace) {
				log.Debugf("No log for namespace %s", namespace)
				return
			}
		}
	}

	if !allow && n.aggregator != nil {
		if err := n.aggregator.Aggregate(e); err == nil {
			log.Debugf("Aggregate %v", e)
			return
		}
		// If aggregate fails due to aggregator size, drop the log to avoid it using
		// up the rateLimiter quota.
		log.Debugf("Fail to aggregate %v, err: %v", e, err)
		(&n.counter.aggregateFails).inc(1)
		return
	}

	if n.rateLimiter.Allow() {
		if b, err := json.Marshal(e); err != nil {
			log.Errorf("Marshal failed: %v", err)
			(&n.counter.typeErrors).inc(1)
			return
		} else {
			if _, err = n.writer.Write(append(b, '\n')); err != nil {
				(&n.counter.logWriteFails).inc(1)
				return
			}
			(&n.counter.generatedLogs).inc(1)
		}
	} else {
		(&n.counter.rateLimitDroppedLogs).inc(1)
		(&n.counter.rateLimitDroppedConnections).inc(1)
	}
}

func (n *networkPolicyLogger) processAggregatedEntry(ae *aggregator.AggregatorEntry) {
	e, ok := ae.Entry.(*PolicyActionLogEntry)
	if !ok {
		log.Errorf("Unexpected type %T", ae.Entry)
		(&n.counter.typeErrors).inc(1)
		return
	}
	e.Count = ae.Count
	if n.rateLimiter.Allow() {
		if b, err := json.Marshal(e); err != nil {
			log.Errorf("Marshal failed: %v", err)
			(&n.counter.typeErrors).inc(1)
			return
		} else {
			if _, err = n.writer.Write(append(b, '\n')); err != nil {
				n.counter.logWriteFails++
				return
			}
			(&n.counter.generatedLogs).inc(1)
		}
	} else {
		(&n.counter.rateLimitDroppedLogs).inc(1)
		(&n.counter.rateLimitDroppedConnections).inc(uint64(ae.Count))
	}
}
