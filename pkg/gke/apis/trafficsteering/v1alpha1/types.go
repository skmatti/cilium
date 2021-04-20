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
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// TrafficSteering defines configuration to route traffic to another node.
type TrafficSteering struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// Spec is the desired configuration for traffic steering.
	Spec TrafficSteeringSpec `json:"spec,omitempty"`
}

// TrafficSteeringSpec provides the specification for traffic steering.
type TrafficSteeringSpec struct {
	// Selector defines what traffic is matched by this spec.
	Selector TrafficSelector `json:"selector"`
	// Traffic selected are tunnelled to this IP.
	DestinationIP string `json:"destinationIP"`
}

// TrafficSelector selects traffic to be routed according to the spec.
// Criterias in this struct are "AND"ed together.
type TrafficSelector struct {
	// Selects nodes to apply the steering.
	NodeSelector metav1.LabelSelector `json:"nodeSelector"`
	// Selects traffic to dst IPs in these CIDRs
	DestinationCIDRs []string `json:"destinationCIDRs"`
}

// +genclient
// +genclient:onlyVerbs=get
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// TrafficSteeringList contains a list of TrafficSteering resources.
type TrafficSteeringList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`

	// Items is a slice of TrafficSteering resources.
	Items []TrafficSteering `json:"items"`
}
