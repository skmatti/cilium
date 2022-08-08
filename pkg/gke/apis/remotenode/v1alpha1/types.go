/*
Copyright 2023 Google LLC

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
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:shortname=rn

// RemoteNode describes the specification of a node in another cluster.
type RemoteNode struct {
	v1.TypeMeta   `json:",inline"`
	v1.ObjectMeta `json:"metadata,omitempty"`

	// Spec describes the specification of a node in another cluster.
	Spec RemoteNodeSpec `json:"spec,omitempty"`
}

// RemoteNodeSpec is a subset of runtime configuration node is another cluster.
type RemoteNodeSpec struct {
	// Public key used by the node for setting up encryption tunnnel.
	PublicKey string `json:"public-key,omitempty"`

	// IP address used by the node for setting encryption tunnel.
	TunnelIP string `json:"tunnel-ip,omitempty"`

	// List of CIDRs used by the node for pods.
	PodCIDRs []string `json:"podCIDRs,omitempty"`
}

// +genclient
// +genclient:onlyVerbs=get
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// RemoteNodeList contains a list of RemoteNode resources.
type RemoteNodeList struct {
	v1.TypeMeta `json:",inline"`
	v1.ListMeta `json:"metadata,omitempty"`

	// Items is a slice of RemoteNode resources.
	Items []RemoteNode `json:"items"`
}
