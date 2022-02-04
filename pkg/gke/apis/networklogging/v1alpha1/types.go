/*
Copyright 2020 Google LLC

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
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:scope=Cluster,shortName=nl

// NetworkLogging describes the specification used by network logging.
// There can be at most one copy of this resource in the cluster.
// This will be enforced using validation proposed in
// https://github.com/kubernetes-sigs/kubebuilder/issues/1074
// If the resource does not exist, logging will be disabled.
type NetworkLogging struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// Spec is the desired configuration for network logging.
	Spec NetworkLoggingSpec `json:"spec,omitempty"`
}

// NetworkLoggingSpec provides the specification for the network logging resource.
// It is applicable to the whole cluster.
type NetworkLoggingSpec struct {
	// Cluster specifies the log options for cluster-level network logging.
	Cluster ClusterLogSpec `json:"cluster"`

	// Node specifies the log options for node-level network logging.
	// The configuration applies to all nodes.
	Node NodeLogSpec `json:"node"`
}

// LogAction specifies the logging action for a given type of traffic.
type LogAction struct {
	// Log specifies if logging is enabled or not. The default value is false.
	// +kubebuilder:default:false
	Log bool `json:"log"`

	// Delegate can only be true if Log is true. Log:false, Delegate:true is invalid.
	// If Delegate is true, then logging will be controlled by the annotation.
	// For policy action logs, it is controlled by annotation on policy resources.
	// Connections that match a policy with annotation "policy.network.gke.io/enable-logging: true"
	// will be logged.
	// For cluster-level flow logs, it is controlled by annotation on namespace.
	// Traffic related to pods in the namespace with annotation "flow.network.gke.io/enable-logging: true”
	// will be logged.
	// For node-level flow logs, it is controlled by annotation on node.
	// Traffic related to nodes with annotation "flow.network.gke.io/enable-logging: true”
	// will be logged.
	// The default value is false.
	// +kubebuilder:default:false
	Delegate bool `json:"delegate"`
}

// ClusterLogSpec contains the log spec for cluster-level network logging.
type ClusterLogSpec struct {
	// Allow specifies the log action for policy-allowed connections.
	Allow LogAction `json:"allow"`
	// Deny specifies the log action for policy-denied connections.
	Deny LogAction `json:"deny"`
	// Flow specifies per flow log actions. Only flows Allowed will be logged.
	Flow LogAction `json:"flow"`
	// FlowAggregationSeconds controls how frequently the packets identified to be the
	// same flow will be recorded. For an active flow, roughly one log record will
	// be generated per FlowAggregationSeconds.
	// If not configured, a default value will be used.
	// +optional
	FlowAggregationSeconds *uint32 `json:"flowAggregationSeconds,omitempty"`
}

// NodeLogSpec contains the log spec for node-level policy action logging.
type NodeLogSpec struct {
	// Allow specifies the log action for policy-allowed connections.
	Allow LogAction `json:"allow"`
	// Deny specifies the log action for policy-denied connections.
	Deny LogAction `json:"deny"`
	// Flow specifies per flow log actions. Only flows Allowed will be logged.
	Flow LogAction `json:"flow"`
	// FlowAggregationSeconds controls how frequently the packets identified to be the
	// same flow will be recorded. For an active flow, roughly one log record will
	// be generated per FlowAggregationSeconds.
	// If not configured, a default value will be used.
	// +optional
	FlowAggregationSeconds *uint32 `json:"flowAggregationSeconds,omitempty"`
}

// +genclient
// +genclient:nonNamespaced
// +genclient:onlyVerbs=get
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// NetworkLoggingList contains a list of NetworkLogging resources.
type NetworkLoggingList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`

	// Items is a slice of NetworkLogging resources.
	Items []NetworkLogging `json:"items"`
}
