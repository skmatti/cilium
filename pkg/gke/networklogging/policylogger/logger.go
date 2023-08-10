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
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/monitor/api"
	policyapi "github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/pkg/policy/correlation"
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
	policyCorrelator correlation.Correlator
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
	configFilePath   string

	// hubblePolicyCorrelation signals that correlation has been performed on the flow object.
	hubblePolicyCorrelation bool

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
	log.WithField("spec", logfields.Repr(spec)).Debug("Update network logging spec")
	new := getLogSpec(spec)
	old := n.getSpec()
	if reflect.DeepEqual(new, old) {
		return false
	}
	log.WithField("old", logfields.Repr(old)).WithField("new", logfields.Repr(new)).Info("Updated logging spec")
	n.setSpec(new)
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
	n.cfg = loadInternalConfig(n.configFilePath)
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
			func() { policyLoggingErrorCount.WithLabelValues(errorReasonAggregateQueue).Inc() })
		n.aggregator.Start()
	}

	go n.run()

	if err := n.dispatcher.AddFlowListener("policy", int32(api.MessageTypePolicyVerdict), n.flowCh,
		func() { policyLoggingErrorCount.WithLabelValues(errorReasonEvenetQueue).Inc() }); err != nil {
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

func (n *networkPolicyLogger) allowedPoliciesForDelegate(policies []*flow.Policy) []*flow.Policy {
	var ret []*flow.Policy
	var key string
	var annotations map[string]string
	for _, p := range policies {
		if p.Kind == "" {
			log.WithField("policy", logfields.Repr(p)).Debug("Policy kind is empty")
			policyLoggingErrorCount.WithLabelValues(errorReasonGetPolicy).Inc()
			continue
		}
		policyStore := n.storeGetter.GetK8sStore(p.Kind)
		if policyStore == nil {
			log.Errorf("Cannot find %s policy store", p.Kind)
			policyLoggingErrorCount.WithLabelValues(errorReasonGetPolicy).Inc()
			continue
		}

		if p.Namespace == "" {
			key = p.Name
		} else {
			key = p.Namespace + "/" + p.Name
		}
		obj, exist, err := policyStore.GetByKey(key)
		if err != nil {
			log.WithField("policy", logfields.Repr(p)).WithField("key", key).Errorf("Failed to fetch policy: %v", err)
			policyLoggingErrorCount.WithLabelValues(errorReasonGetPolicy).Inc()
			continue
		}
		// Maybe the policy is already deleted.
		if !exist {
			log.WithField("kind", p.Kind).WithField("key", key).Debug("object not found")
			policyLoggingErrorCount.WithLabelValues(errorReasonGetPolicy).Inc()
			continue
		}

		switch p.Kind {
		case "NetworkPolicy":
			np := k8s.ObjToV1NetworkPolicy(obj)
			if np == nil {
				log.WithField("kind", p.Kind).WithField("key", key).Error("Unable to convert object to network policy")
				policyLoggingErrorCount.WithLabelValues(errorReasonObjectConversion).Inc()
				continue
			}
			annotations = np.GetAnnotations()
		case "CiliumNetworkPolicy", "CiliumClusterwideNetworkPolicy":
			cnp := k8s.ObjToSlimCNP(obj)
			if cnp == nil {
				log.WithField("kind", p.Kind).WithField("key", key).Error("Unable to convert object to cilium network policy")
				policyLoggingErrorCount.WithLabelValues(errorReasonObjectConversion).Inc()
				continue
			}
			annotations = cnp.GetAnnotations()
		default:
			log.WithField("kind", p.Kind).WithField("key", key).Errorf("Unsupported policy kind %s", p.Kind)
			policyLoggingErrorCount.WithLabelValues(errorReasonObjectConversion).Inc()
			continue
		}
		if annotations[AnnotationEnableAllowLogging] == "true" {
			ret = append(ret, p)
		}
	}
	return ret
}

func (n *networkPolicyLogger) shouldLogNamespace(name string) bool {
	namespaceStore := n.storeGetter.GetK8sStore("namespace")
	if namespaceStore == nil {
		log.Error("Cannot find the namespace store")
		policyLoggingErrorCount.WithLabelValues(errorReasonGetNamespace).Inc()
		return false
	}
	obj, exist, err := namespaceStore.GetByKey(name)
	if err != nil {
		log.Errorf("Fail to fetch namespace %q: %v", name, err)
		policyLoggingErrorCount.WithLabelValues(errorReasonGetNamespace).Inc()
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
	allow := policyapi.IsFlowAllowed(f)
	policyLoggingEventCount.WithLabelValues(verdictLabel(allow)).Inc()

	spec := n.getSpec()
	if !spec.log {
		log.Debugf("Logging is disabled. Flow: %v", f)
		return
	}
	e, err := n.flowToPolicyActionLogEntry(f)
	if err != nil {
		log.Debugf("Flow parsing failed. Flow: %v, err: %v", f, err)
		policyLoggingErrorCount.WithLabelValues(errorReasonParsing).Inc()
		return
	}

	// Don't log the connections allowed by default, such as health checks.
	if e.SkipLogging(n.cfg.logUncorrelatedEntry) {
		log.Debugf("Skip as matched policy slice is nil. Flow: %v", f)
		return
	}

	isNode := e.isNodeTraffic()
	action := spec.getLogAction(isNode, allow)
	if !action.log {
		log.WithField("action", action).Debug("Logging is disabled")
		return
	}

	if action.delegate && !n.shouldLogDelegatedEvent(f, e, allow) {
		return
	}

	// Flow has been completely processed.

	if !allow && n.aggregator != nil {
		if err := n.aggregator.Aggregate(e); err != nil {
			// If aggregate fails due to aggregator size, drop the log to avoid it using
			// up the rateLimiter quota.
			log.Debugf("Fail to aggregate %v, err: %v", e, err)
			policyLoggingDropCount.WithLabelValues(enforcementLabel(isNode), dropReasonAggregation).Inc()
			return
		}
		log.Debugf("Aggregate %v", e)
		return
	}

	if allow {
		policyLoggingAllowedFlowProcessedCount.WithLabelValues(correlatedLabel(e.Correlated)).Inc()
	}

	if n.rateLimiter.Allow() {
		if b, err := json.Marshal(e); err != nil {
			log.Errorf("Marshal failed: %v", err)
			policyLoggingErrorCount.WithLabelValues(errorReasonMarshal).Inc()
			return
		} else {
			if _, err = n.writer.Write(append(b, '\n')); err != nil {
				policyLoggingErrorCount.WithLabelValues(errorReasonWrite).Inc()
				return
			}
			policyLoggingLogCount.WithLabelValues(enforcementLabel(isNode), verdictLabel(allow)).Inc()
			delay := float64(time.Now().Sub(e.Timestamp).Microseconds())
			policyLoggingAllowLatencies.Observe(delay)
		}
	} else {
		policyLoggingDropCount.WithLabelValues(enforcementLabel(isNode), dropReasonRateLimit).Inc()
	}
}

func (n *networkPolicyLogger) shouldLogDelegatedEvent(f *flow.Flow, e *PolicyActionLogEntry, allow bool) bool {
	switch {
	case !e.Correlated && n.cfg.logUncorrelatedEntry:
		// Note: we are not respecting delegation here.
		//
		// Flow is uncorrelated and endpoint may be remote. Unable to resolve
		// policies and (even with namespace-sameness) namespace may not be
		// present in the cluster.
		log.Debug("allow logging uncorrelated flow")
		return true
	case allow:
		logPolicies := n.allowedPoliciesForDelegate(e.Policies)

		if len(logPolicies) == 0 {
			log.WithField("policies", e.Policies).Debug("No matching policy")
			return false
		}
		e.Policies = logPolicies
	default:
		var namespace string
		if e.Connection.Direction == ConnectionDirectionIngress {
			namespace = e.Dest.Namespace
		} else {
			namespace = e.Src.Namespace
		}
		if !n.shouldLogNamespace(namespace) {
			log.WithField("namespace", namespace).Debug("Namespace is not configured for deny logging")
			return false
		}
	}
	return true
}

func (n *networkPolicyLogger) processAggregatedEntry(ae *aggregator.AggregatorEntry) {
	e, ok := ae.Entry.(*PolicyActionLogEntry)
	if !ok {
		log.Errorf("Unexpected type %T", ae.Entry)
		policyLoggingErrorCount.WithLabelValues(errorReasonObjectConversion).Inc()
		return
	}
	e.Count = ae.Count
	isNode := e.isNodeTraffic()
	if n.rateLimiter.Allow() {
		if b, err := json.Marshal(e); err != nil {
			log.Errorf("Marshal failed: %v", err)
			policyLoggingErrorCount.WithLabelValues(errorReasonMarshal).Inc()
			return
		} else {
			if _, err = n.writer.Write(append(b, '\n')); err != nil {
				policyLoggingErrorCount.WithLabelValues(errorReasonWrite).Inc()
				return
			}
			policyLoggingLogCount.WithLabelValues(enforcementLabel(isNode), verdictLabel(false)).Inc()
			delay := time.Now().Sub(e.Timestamp).Seconds()
			policyLoggingDenyLatencies.Observe(delay)
		}
	} else {
		policyLoggingDropCount.WithLabelValues(enforcementLabel(isNode), dropReasonRateLimit).Inc()
	}
}
