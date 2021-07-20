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
	endpointGetter   getters.EndpointGetter
	flowCh           chan *flow.Flow
	stopCh           chan struct{}
	doneCh           chan struct{}
	writer           writer.Writer
	rateLimiter      *ratelimiter.RateLimiter
	aggregator       *aggregator.Aggregator
	aggregatorCh     chan *aggregator.AggregatorEntry
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
// UpdateLoggingSpec updates the network logging spec. Return whether the
// configuration has changed.
func (n *networkPolicyLogger) UpdateLoggingSpec(spec *v1alpha1.NetworkLoggingSpec) bool {
	curr := getLogSpec(spec)
	old := n.getSpec()
	if reflect.DeepEqual(curr, old) {
		return false
	}
	log.WithFields(logrus.Fields{"old": old, "curr": curr}).Info("Update logging spec")
	n.setSpec(curr)
	node := true
	if spec == nil {
		policyLoggingEnabled.WithLabelValues(enforcementLabel(!node)).Set(0)
		policyLoggingEnabled.WithLabelValues(enforcementLabel(node)).Set(0)
	} else {
		if spec.Cluster.Allow.Log || spec.Cluster.Deny.Log {
			policyLoggingEnabled.WithLabelValues(enforcementLabel(!node)).Set(1)
		} else {
			policyLoggingEnabled.WithLabelValues(enforcementLabel(!node)).Set(0)
		}
		if spec.Node.Allow.Log || spec.Node.Deny.Log {
			policyLoggingEnabled.WithLabelValues(enforcementLabel(node)).Set(1)
		} else {
			policyLoggingEnabled.WithLabelValues(enforcementLabel(node)).Set(0)
		}
	}
	return true
}

// Start the network policy logger. It returns a callback function to set the policy_logging_ready.
// state to be true after the caller is ready when error is nil.
func (n *networkPolicyLogger) Start() (error, func()) {
	n.cfg = loadInternalConfig(configFile)
	w, err := writer.NewFileWriter(n.cfg.logFilePath, n.cfg.logFileName,
		int(n.cfg.logFileMaxSize), int(n.cfg.logFileMaxBackups))
	if err != nil {
		err = fmt.Errorf("failed to create FileWriter (path = %q, name = %q): %w", n.cfg.logFilePath, n.cfg.logFileName, err)
		return err, nil
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
			time.Second, int(n.cfg.denyAggregationMapSize), n.aggregatorCh,
			func() { policyLoggingErrorCount.WithLabelValues(errorReasonAggregateQueue).Add(1) })
		n.aggregator.Start()
	}

	go n.run()

	if err := n.dispatcher.AddFlowListener("policy", int32(api.MessageTypePolicyVerdict), n.flowCh,
		func() { policyLoggingErrorCount.WithLabelValues(errorReasonEvenetQueue).Add(1) }); err != nil {
		err = fmt.Errorf("failed to add policy verdict listener: type %d, %w", api.MessageTypePolicyVerdict, err)
		log.Error(err)
		n.Stop()
		return err, nil
	}
	return nil, func() { policyLoggingReady.Set(1) }
}

// Stop stops network policy logger.
func (n *networkPolicyLogger) Stop() {
	close(n.stopCh)
	<-n.doneCh
}

// run listens and process the flow.
func (n *networkPolicyLogger) run() {
	log.Infof("Logger started with cfg: %s", n.cfg.print())
	for {
		select {
		case f := <-n.flowCh:
			n.processFlow(f)
		case ae := <-n.aggregatorCh:
			n.processAggregatedEntry(ae)
		case <-n.stopCh:
			log.Info("Remove flow listener")
			n.dispatcher.RemoveFlowListener("policy", int32(api.MessageTypePolicyVerdict))
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
		policyLoggingErrorCount.WithLabelValues(errorReasonGetPolicy).Add(1)
		return policies
	}
	var ret []*Policy
	for _, p := range policies {
		key := p.Namespace + "/" + p.Name
		obj, exist, err := policyStore.GetByKey(key)
		if err != nil {
			log.Errorf("Fail to fetch policy %q: %v", key, err)
			policyLoggingErrorCount.WithLabelValues(errorReasonGetPolicy).Add(1)
			continue
		}
		// Maybe the policy is already deleted.
		if !exist {
			policyLoggingErrorCount.WithLabelValues(errorReasonGetPolicy).Add(1)
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
		policyLoggingErrorCount.WithLabelValues(errorReasonGetNamespace).Add(1)
		return false
	}
	obj, exist, err := namespaceStore.GetByKey(name)
	if err != nil {
		log.Errorf("Fail to fetch namespace %q: %v", name, err)
		policyLoggingErrorCount.WithLabelValues(errorReasonGetNamespace).Add(1)
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
	allow := isAllow(f)
	policyLoggingEventCount.WithLabelValues(verdictLabel(allow)).Add(1)

	spec := n.getSpec()
	if !spec.log {
		log.Debugf("Logging is disabled. Flow: %v", f)
		return
	}
	e, err := n.flowToPolicyActionLogEntry(f)
	if err != nil {
		log.Debugf("Flow parsing failed. Flow: %v, err: %v", f, err)
		policyLoggingErrorCount.WithLabelValues(errorReasonParsing).Add(1)
		return
	}
	isNode := isNodeTraffic(e)
	if isNode {
		log.Debugf("Node policy log is not supported. Flow: %v", f)
		return
	}
	// Don't log the connections allowed by default, such as health checks.
	if allow && e.Policies == nil {
		log.Debugf("Skip as matched policy is empty. Flow: %v", f)
		return
	}

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
				namespace = e.Dest.Namespace
			} else {
				namespace = e.Src.Namespace
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
		policyLoggingDropCount.WithLabelValues(enforcementLabel(isNode), dropReasonAggregation).Add(1)
		return
	}

	if n.rateLimiter.Allow() {
		if b, err := json.Marshal(e); err != nil {
			log.Errorf("Marshal failed: %v", err)
			policyLoggingErrorCount.WithLabelValues(errorReasonMarshal).Add(1)
			return
		} else {
			if _, err = n.writer.Write(append(b, '\n')); err != nil {
				policyLoggingErrorCount.WithLabelValues(errorReasonWrite).Add(1)
				return
			}
			policyLoggingLogCount.WithLabelValues(enforcementLabel(isNode), verdictLabel(allow)).Add(1)
			delay := float64(time.Now().Sub(e.Timestamp).Microseconds())
			policyLoggingAllowLatencies.Observe(delay)
		}
	} else {
		policyLoggingDropCount.WithLabelValues(enforcementLabel(isNode), dropReasonRateLimit).Add(1)
	}
}

func (n *networkPolicyLogger) processAggregatedEntry(ae *aggregator.AggregatorEntry) {
	e, ok := ae.Entry.(*PolicyActionLogEntry)
	if !ok {
		log.Errorf("Unexpected type %T", ae.Entry)
		policyLoggingErrorCount.WithLabelValues(errorReasonObjectConversion).Add(1)
		return
	}
	e.Count = ae.Count
	isNode := isNodeTraffic(e)
	if n.rateLimiter.Allow() {
		if b, err := json.Marshal(e); err != nil {
			log.Errorf("Marshal failed: %v", err)
			policyLoggingErrorCount.WithLabelValues(errorReasonMarshal).Add(1)
			return
		} else {
			if _, err = n.writer.Write(append(b, '\n')); err != nil {
				policyLoggingErrorCount.WithLabelValues(errorReasonWrite).Add(1)
				return
			}
			policyLoggingLogCount.WithLabelValues(enforcementLabel(isNode), verdictLabel(false)).Add(1)
			delay := time.Now().Sub(e.Timestamp).Seconds()
			policyLoggingDenyLatencies.Observe(delay)
		}
	} else {
		policyLoggingDropCount.WithLabelValues(enforcementLabel(isNode), dropReasonRateLimit).Add(1)
	}
}
