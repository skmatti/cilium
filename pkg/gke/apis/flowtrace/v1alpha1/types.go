/*
Copyright 2026 Google LLC

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
	types "k8s.io/apimachinery/pkg/types"
)

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:object:root=true
// +kubebuilder:storageversion
// +kubebuilder:resource:path=flowtraces,scope=Cluster,singular=flowtrace
// +kubebuilder:subresource:status

// FlowTrace is the Schema for the FlowTrace API
type FlowTrace struct {
	// +deepequal-gen=false
	metav1.TypeMeta `json:",inline"`
	// +deepequal-gen=false
	metav1.ObjectMeta `json:"metadata,omitempty"`
	// Spec defines the desired state of the FlowTrace Resource.
	// It includes all parameters for defining the network flow's 5-tuple and traffic profile
	Spec FlowTraceSpec `json:"spec,omitempty"`
	// Status represents the observed state of the FlowTrace CR, detailing
	// its current conditions, the associated generator entity, and any error states.
	Status FlowTraceStatus `json:"status,omitempty"`
}

// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="FlowTrace specification is immutable and cannot be changed after creation."

// FlowTraceSpec defines the desired or expected state of the FlowTrace resource.
type FlowTraceSpec struct {
	// SourceEndpoint denotes the source endpoint from where the network flows would be generated.
	// +kubebuilder:validation:Required
	SourceEndpoint FlowEndpoint `json:"sourceEndpoint"`
	// DestinationIP denotes the IP of the destination endpoint that would receive the generated network flows.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Format=ipv4
	DestinationIP string `json:"destinationIP"`
	// TraceID uniquely distinguishes flows generated from a particular FlowTrace CR.
	// TraceID is injected into the packet into an IPv4 Option Header, and can be used to trace generated flows.
	// +kubebuilder:validation:Required
	TraceID uint32 `json:"traceID"`
	// FlowProfile defines the nature and the configuration of the traffic flows to be generated
	// across the source and destination endpoint (e.g., protocol, packet size, rate).
	// +kubebuilder:validation:Required
	FlowProfile FlowProfile `json:"flowProfile"`
}

// +kubebuilder:validation:XValidation:rule="has(self.ip) != has(self.k8sPodKey)",message="Exactly one of 'ip' or 'k8sPodKey' must be specified."

// FlowEndpoint identifies a network flow source or destination.
// It can be identified either by a static IP address or by a reference to a Kubernetes Pod.
type FlowEndpoint struct {
	// IP is the static IP address of the endpoint.
	// This field should be used for service VIP’s, external endpoints or unmanaged entities.
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Format=ipv4
	IP string `json:"ip,omitempty"`
	// K8sPodKey is a reference to a Kubernetes Pod in the cluster.
	// +kubebuilder:validation:Optional
	K8sPodKey types.NamespacedName `json:"k8sPodKey"`
}

// FlowProfile defines the characteristics of the network flow.
type FlowProfile struct {
	// ProtocolConfig specifies the network protocol and protocol-specific configurations pertaining to the flow.
	// +kubebuilder:validation:Required
	ProtocolConfig ProtocolConfiguration `json:"protocolConfig"`
	// FlowConfig holds general flow properties, such as total duration, interval between flows, and total flow count.
	// If empty, default values are applied.
	FlowConfig *FlowConfiguration `json:"flowConfig,omitempty"`
}

// ProtocolConfiguration specifies the protocol and protocol-specific settings for the flow.
type ProtocolConfiguration struct {
	// TCPConfiguration defines configuration for TCP traffic flows.
	// +kubebuilder:validation:Required
	TCP TCPConfiguration `json:"tcp"`
}

// TCPConfiguration defines configuration for TCP traffic flows.
type TCPConfiguration struct {
	// SourcePort defines the source port for TCP flow generation.
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	// +kubebuilder:validation:Optional
	SourcePort uint16 `json:"sourcePort,omitempty"`
	// DestinationPort defines the destination port for receiving TCP flows.
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	// +kubebuilder:validation:Required
	DestinationPort uint16 `json:"destinationPort"`
}

// +kubebuilder:validation:XValidation:rule="!(has(self.duration) && has(self.flowCount))", message="duration and flowCount are mutually exclusive; only one can be specified."

// FlowConfiguration holds general parameters for generating network flows.
type FlowConfiguration struct {
	// Interval between two subsequent flows being generated, in seconds.
	// A value of 0 means flows are generated immediately without an interval.
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=10
	// +kubebuilder:default=0
	// +kubebuilder:validation:Optional
	Interval uint32 `json:"interval,omitempty"`
	// Total duration (in seconds) for which flows should be generated.
	// As only one of duration and flowCount can be specified, if both are unset, duration defaults to 300 seconds (5 minutes)
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=3600
	// +kubebuilder:validation:Optional
	Duration uint32 `json:"duration,omitempty"`
	// Number of sequential flows to be initiated by the generator.
	// Cannot be specified if Duration is specified.
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=50
	// +kubebuilder:validation:Optional
	FlowCount uint32 `json:"flowCount,omitempty"`
}

// FlowTraceStatus defines the observed state of FlowTrace CRs
type FlowTraceStatus struct {
	// ObservedGeneration is the latest generation observed by the controller.
	// It is used to reconcile state and determine if the CR has been processed since the last update.
	// +kubebuilder:validation:Optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`
	// Name on the node on which the source IP is hosted. Note that source IP can itself be the node.
	// Note that this is a selectable field, and will be available for selection via fieldSelectors.
	// +kubebuilder:selectable
	// +kubebuilder:validation:Optional
	SourceNode string `json:"sourceNode,omitempty"`
	// Conditions represent the latest available observations of the FlowTraceStatus’s state.
	// Common conditions include NotReady, Ready, Flowing, Error, and Completed.
	//
	// type: Ready
	// state: true
	// reason: Complete
	//
	// type: Active
	// state: False
	// reason: Duration exceeded
	// message: Flow has completed due to duration
	//
	// +kubebuilder:validation:Optional
	// +patchStrategy=merge
	// +patchMergeKey=type
	// +listType=map
	// +listMapKey=type
	// +deepequal-gen=false
	Conditions []metav1.Condition `json:"conditions,omitempty" patchStrategy:"merge" patchMergeKey:"type"`
}

// +genclient:nonNamespaced
// +genclient:onlyVerbs=get
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +k8s:openapi-gen=false
// +deepequal-gen=false

// FlowTraceList contains a list of FlowTrace
type FlowTraceList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []FlowTrace `json:"items"`
}
