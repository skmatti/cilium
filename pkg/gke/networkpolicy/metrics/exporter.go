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

package metrics

import (
	"fmt"
	"strings"

	"github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/pkg/gke/dispatcher"
	"github.com/cilium/cilium/pkg/gke/util"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/monitor/api"
)

const (
	// Name for flow listener.
	flowListenerName = "verdict_listener_for_metric_exporter"
)

// exporter struct is used for defining fields that are used for communicating with pkg/gke/flow/plugin.go to process flows received from hubble
type exporter struct {
	dispatcher dispatcher.Dispatcher // dispatcher is used for registering and removing flowListener
	flowCh     chan *flow.Flow       // flowCh is channel used for receiving flows from hubble
	stopCh     chan struct{}         // stopCh is used for stopping the go routine
	doneCh     chan struct{}         // doneCh is used for graceful termination of go routine
}

// metricLabels is a struct that defines the prometheus metric labels for the policy_event_count metric
type metricLabels struct {
	namespace    string //namespace is name of the namespace of the pod on which network policy is enforced
	podName      string //podName is name of the on which network policy is enforced
	verdict      string //verdict is network policy verdict for the event
	workloadName string //workloadName is the name of the workload that pod might be part of
	workloadKind string //workloadKind is the type of the workload that pod might be part of
	direction    string //direction is traffic direction from the scope of the pod on which network policy is enforced
}

func (e *exporter) start() error {
	// using same QueueSize as network policy logger for consistency
	e.flowCh = make(chan *flow.Flow, util.QueueSize)
	e.stopCh = make(chan struct{})
	e.doneCh = make(chan struct{})

	go e.run()

	dropNotifyFunc := func() { log.Debug("Received a flow drop from hubble") }
	err := e.dispatcher.AddFlowListener(flowListenerName, int32(api.MessageTypePolicyVerdict), e.flowCh, dropNotifyFunc)
	if err != nil {
		err = fmt.Errorf("failed to add policy verdict(type %d) listener for metrics exporter: %w", api.MessageTypePolicyVerdict, err)
		log.Error(err)
		e.stop()
		return err
	}
	return nil
}

func (e *exporter) stop() {
	close(e.stopCh)
	<-e.doneCh
}

func (e *exporter) run() {
	log.Info("Exporter is starting to listen on flow, to be received on flowCh")
	for {
		select {
		case f := <-e.flowCh:
			log.Debug("Metric exporter received flow")
			e.processFlowAndRecordMetric(f)
		case <-e.stopCh:
			log.Info("Removing flow listener")
			e.dispatcher.RemoveFlowListener(flowListenerName, int32(api.MessageTypePolicyVerdict))
			e.flowCh = nil
			close(e.doneCh)
			return
		}
	}
}

// Determine if flow is valid by extracting all the fields and then record it with prometheus metric
func (e *exporter) processFlowAndRecordMetric(f *flow.Flow) {
	labels, ready := e.isFlowValid(f)
	if ready {
		policyEventCount.WithLabelValues(labels.namespace, labels.podName, labels.verdict, labels.workloadName, labels.workloadKind, labels.direction).Add(1)
	}
}

// Determine if flow is valid based on 4 conditions mentioned in the comments inside the function.
// Also, populate the metricLabels struct and return metricLabels
func (e *exporter) isFlowValid(f *flow.Flow) (metricLabels, bool) {
	var labels metricLabels

	switch f.GetVerdict() {
	case flow.Verdict_FORWARDED:
		labels.verdict = "allow"
	case flow.Verdict_DROPPED:
		labels.verdict = "deny"
	default:
		// Invalid Condition 1: Verdict should either be forwarded or dropped
		log.Debugf("Unexpected verdict %s for flow %+v", f.GetVerdict(), f)
		return labels, false
	}
	labels.direction = strings.ToLower(f.GetTrafficDirection().String())

	switch labels.direction {
	case strings.ToLower(flow.TrafficDirection_INGRESS.String()):
		// Static pods can exist without any workload, in that case we won't report workload_name & workload_kind
		if len(f.Destination.Workloads) > 0 {
			labels.workloadName = f.Destination.Workloads[0].Name
			labels.workloadKind = f.Destination.Workloads[0].Kind
		}
		labels.namespace = f.Destination.Namespace
		labels.podName = f.Destination.PodName
	case strings.ToLower(flow.TrafficDirection_EGRESS.String()):
		// Static pods can exist without any workload, in that case we won't report workload_name & workload_kind
		if len(f.Source.Workloads) > 0 {
			labels.workloadName = f.Source.Workloads[0].Name
			labels.workloadKind = f.Source.Workloads[0].Kind
		}
		labels.namespace = f.Source.Namespace
		labels.podName = f.Source.PodName
	default:
		// Invalid Condition: TrafficDirection should either be Egress or Ingress
		log.Debugf("Unexpected traffic direction %s for flow %+v", f.GetTrafficDirection(), f)
		return labels, false
	}

	// everything looks good, set ready to true
	log.Debugf("Labels %+v are ready to be exported as metric fields", labels)
	return labels, true
}

func newExporter(dispatcher dispatcher.Dispatcher) *exporter {
	e := &exporter{
		dispatcher: dispatcher,
	}
	metrics.MustRegister(metricsCollector()...)
	log.Info("Sucessfully registered metrics")
	return e
}
