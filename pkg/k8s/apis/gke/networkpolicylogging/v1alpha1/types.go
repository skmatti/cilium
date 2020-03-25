/*
Copyright 2020 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// NetworkPolicyLogging describes the specification used by network policy action
// logging.
type NetworkPolicyLogging struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// Spec is the desired configuration for network policy action logging.
	Spec NetworkPolicyLoggingSpec `json:"spec,omitempty"`

	// Status is the status of this network policy action logging object.
	Status NetworkPolicyLoggingStatus `json:"status,omitempty"`
}

// NetworkPolicyLoggingSpec provides the specification for a network policy action
// logging.
type NetworkPolicyLoggingSpec struct {
	// ApiGroup specifies for which api group this logging configuration shall
	// apply to.
	ApiGroup string `json:"apiGroup"`

	// Kind specifies for kind under the api group this logging configuration
	// shall apply to.
	Kind string `json:"kind"`

	// LogDeny specifies how the dropped flows due to the network policy for the
	// given apiGroup and Kind will be logged.
	LogDeny LogSpec `json:"logDeny"`

	// LogAllow specifies how the allowed flows due to the network policy for the
	// given apiGroup and Kind will be logged.
	LogAllow LogSpec `json:"logAllow"`

	// MaxLogPerMinute specifies the maximum number of logs that can be generated
	// per minute per node.
	MaxLogPerMinute int `json:"maxLogPerMinute"`
}

// LogSpec contains the flow configuration.
type LogSpec struct {
	// Mode specifies the mode to control logging for allowed traffic. It can be
	// either “Always”, “Never” or “Delegate” which delegates the logging
	// decision to each policy object.
	Mode string `json:"mode"`

	// AggregationIdleSeconds specifies the time period of no new connections to
	// end aggregation. If it is configured greater than 0, logs are aggregated
	// for traffic with the same src IP, dst IP, dst Port, protocol, and direction
	// except the first one. If no new flow happens within the last
	// AggregationIdleSeconds, aggregation ends and a log will be generated with
	// the number of connections during the aggregation period.
	// +optional
	AggregationIdleSeconds int `json:"aggregationIdleSeconds,omitempty"`

	// AggregationMaxSeconds specifies the max time period in seconds for
	// aggregating the logs. If aggregation period exceeds this time, even if
	// AggregationIdleSeconds condition doesn’t satisfy, a log will be generated
	// with the already aggregated flow counts. This value will be ignored if
	// AggregationIdleSeconds is zero or not configured. If this value is not
	// configured, AggregationIdleSeconds becomes the only trigger to stop
	// aggregation (other than the program exits).
	// +optional
	AggregationMaxSeconds int `json:"aggregationMaxSeconds,omitempty"`
}

// NetworkPolicyLoggingStatus contains the status for network policy logging
// resource.
type NetworkPolicyLoggingStatus struct {
	// State specifies the current state of the policy logging resource.
	State *string `json:"state,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// NetworkPolicyLoggingList contains a list of NetworkPolicyLogging resources.
type NetworkPolicyLoggingList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`

	// Items is a slice of Network Policy logging resources.
	Items []NetworkPolicyLogging `json:"items"`
}
