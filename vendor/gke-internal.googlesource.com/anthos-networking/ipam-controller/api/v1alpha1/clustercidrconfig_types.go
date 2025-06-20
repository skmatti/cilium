/*
Copyright 2021.

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

const HostLocal = "host-local"

// CIDRConfig defines the CIDR and Mask size per IP Family(IPv4/IPv6)
type CIDRConfig struct {
	// Nodes may only have 1 range from each family.
	// An IP block in CIDR notation ("10.0.0.0/8", "fd12:3456:789a:1::/64")
	CIDR string `json:"cidr" protobuf:"bytes,1,name=cidr"`

	// PerNodeMaskSize is the mask size for node cidr.
	// IPv4/IPv6 Netmask size (e.g. 25 -> "/25" or 112 -> "/112") to allocate to a node.
	// Users would have to ensure that the kubelet doesn't try to schedule
	// more pods than are supported by the node's netmask (i.e. the kubelet's
	// --max-pods flag)
	PerNodeMaskSize int32 `json:"perNodeMaskSize" protobuf:"bytes,3,name=perNodeMaskSize"`
}

// ClusterCIDRConfigSpec defines the desired state of ClusterCIDRConfig
type ClusterCIDRConfigSpec struct {
	// NodeSelector defines which nodes the config is applicable to.
	// An empty NodeSelector functions as a default that applies to all nodes.
	// +kubebuilder:validation:Optional
	NodeSelector *metav1.LabelSelector `json:"nodeSelector,omitempty" protobuf:"bytes,2,opt,name=nodeSelector"`

	// IPv4 defines the IPv4 CIDR and the PerNodeMaskSize
	// Atleast one of the IPv4 or IPv6 must be provided
	// +kubebuilder:validation:Optional
	IPv4 *CIDRConfig `json:"ipv4,omitempty" protobuf:"bytes,2,opt,name=ipv4"`

	// IPv6 defines the IPv6 CIDR and the PerNodeMaskSize
	// Atleast one of the IPv4 or IPv6 must be provided
	// +kubebuilder:validation:Optional
	IPv6 *CIDRConfig `json:"ipv6,omitempty" protobuf:"bytes,2,opt,name=ipv6"`

	// Network defines the name of the network to which this ClusterCIDRConfig points to.
	// The IPv4/IPv6 field above will be considered as the CIDR range of this network from which
	// the IPAM controller will carve out the per node ranges using existing algorithm.
	// +kubebuilder:validation:MinLength=1
	// +optional
	Network *string `json:"network,omitempty" protobuf:"bytes,2,opt,name=network"`
}

type ClusterCIDRConfigStatusType string
type ClusterCIDRConfigStatusReason string
type ClusterCIDRConfigMessage string

var (
	// If the "active" condition is true, this ClusterCIDRConfig can be used by
	// the controller to allocate PodCIDRs for matching nodes.
	ClusterCIDRConfigActive    ClusterCIDRConfigStatusType = "active"
	ClusterCIDRConfigActiveMsg ClusterCIDRConfigMessage    = "ClusterCIDRConfig created and is Active"

	// If the "terminating" condition is true, this ClusterCIDRConfig was deleted
	// by a user and is being garbage collected. When all Nodes using PodCIDRs
	// from this range are deleted, the ClusterCIDRConfig will also be deleted.
	ClusterCIDRConfigTerminating ClusterCIDRConfigStatusType = "terminating"

	// If set as the reason on a true ClusterCIDRConfigActive condition, the
	// ClusterCIDRConfig is valid and has CIDRs available to be allocated
	ClusterCIDRConfigAvailable ClusterCIDRConfigStatusReason = "valid_available_cidr"

	// If set as the reason on a false ClusterCIDRConfigActive condition, the
	// ClusterCIDRConfig no longer has any free IP blocks.
	ClusterCIDRConfigExhausted ClusterCIDRConfigStatusReason = "cidr_exhausted"

	// If set as the reason on a true ClusterCIDRConfigTerminating condition,
	// the ClusterCIDRConfig was used to allocate a Node's PodCIDR.
	ClusterCIDRConfigInUse ClusterCIDRConfigStatusReason = "cidr_in_use"
)

// ClusterCIDRConfigStatus defines the observed state of ClusterCIDRConfig
type ClusterCIDRConfigStatus struct {
	// Conditions contain details for the last reported state of ClusterCIDRConfig.
	//
	// +patchMergeKey=type
	// +patchStrategy=merge
	// +listType=map
	// +listMapKey=type
	// +kubebuilder:validation:Optional
	Conditions []metav1.Condition `json:"conditions,omitempty" patchStrategy:"merge" patchMergeKey:"type" protobuf:"bytes,1,rep,name=conditions"`
}

//+genclient
//+kubebuilder:object:root=true
//+kubebuilder:resource:scope=Cluster,shortName=ccc
//+kubebuilder:subresource:status

// ClusterCIDRConfig is the Schema for the clustercidrconfigs API
type ClusterCIDRConfig struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   ClusterCIDRConfigSpec   `json:"spec,omitempty"`
	Status ClusterCIDRConfigStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// ClusterCIDRConfigList contains a list of ClusterCIDRConfig
type ClusterCIDRConfigList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ClusterCIDRConfig `json:"items"`
}

func init() {
	SchemeBuilder.Register(&ClusterCIDRConfig{}, &ClusterCIDRConfigList{})
}
