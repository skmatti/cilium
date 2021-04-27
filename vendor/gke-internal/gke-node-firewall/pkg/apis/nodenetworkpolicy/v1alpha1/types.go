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

// Protocol defines network protocols supported for node network policy.
type Protocol string

const (
	// ProtocolTCP is the TCP protocol.
	ProtocolTCP Protocol = "TCP"
	// ProtocolUDP is the UDP protocol.
	ProtocolUDP Protocol = "UDP"
)

// +genclient
// +genclient:nonNamespaced
// +kubebuilder:object:root=true
// +kubebuilder:resource:shortName=nnp,scope=Cluster
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// NodeNetworkPolicy describes what network traffic is allowed for a set of
// Nodes.
type NodeNetworkPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// Spec contains the specification of NodeNetworkPolicy.
	// +optional
	Spec NodeNetworkPolicySpec `json:"spec,omitempty"`
}

// NodeNetworkPolicySpec provides the specification of a NodeNetworkPolicy.
type NodeNetworkPolicySpec struct {
	// Selects the nodes to which this NodeNetworkPolicy object applies. The
	// array of ingress rules are applied to any nodes selected by this field.
	// Multiple network policies can select the same set of nodes. In this case,
	// the ingress rules for each are combined additively. This field is NOT
	// optional and follows standard label selector semantics. An empty
	// nodeselector matches all nodes in this cluster.
	NodeSelector metav1.LabelSelector `json:"nodeSelector"`

	// Logging specifies the logging options for connection matching this policy.
	// +optional
	Logging *LoggingSpec `json:"logging,omitempty"`

	// List of ingress rules to be applied to the selected nodes. Connection is allowed
	// to a node if there are no NodeNetworkPolies selecting the node
	// OR if the connection matches at least one ingress rule
	// across all of the NodeNetworkPolicy objects whose nodeSelector matches
	// the node. If this field is empty, then this NodeNetworkPolicy does not allow any
	// traffic (and serves solely to ensure that the nodes it selects are isolated by default)
	// +optional
	Ingress []NodeNetworkPolicyIngressRule `json:"ingress,omitempty"`
}

// LoggingSpec provides the spec for logging.
type LoggingSpec struct {
	// If true, connections that match this node network policy will be logged.
	Enable bool `json:"enable"`
}

// NodeNetworkPolicyIngressRule describes a particular set of connections that are
// allowed to the nodes matched by a NodeNetworkPolicySpec's nodeSelector.
// The connection must match both Ports and From if they are non-empty.
// An empty rule means allowing all ingress connections.
// The firewall is stateful, so the reply traffic to an egress connection
// that is initiated by the node are automatically allowed.
type NodeNetworkPolicyIngressRule struct {
	// List of ports which should be made accessible on the nodes selected for this
	// rule. Each item in this list is combined using a logical OR. If this
	// field is empty or missing, this rule matches all ports and protocols (traffic
	// not restricted by port and protocol). If this field is present and contains
	// at least one item, then this rule allows traffic only if the traffic matches
	// at least one port in the list.
	// +optional
	Ports []NodeNetworkPolicyPort `json:"ports,omitempty"`

	// List of sources that are allowed to access the nodes selected for this
	// rule. Items in this list are combined using a logical OR operation. If
	// this field is empty or missing, this rule allows all sources. If this
	// field is present and contains at least one item, this rule allows traffic
	// only if the traffic matches at least one item in the from list.
	// +optional
	From []NodeNetworkPolicyPeer `json:"from,omitempty"`
}

// NodeNetworkPolicyPeer describes a peer to allow traffic from.
type NodeNetworkPolicyPeer struct {
	// IPBlock defines a particular IP block that a peer can belong to.
	IPBlock *IPBlock `json:"ipBlock,omitempty"`
}

// NodeNetworkPolicyPort describes a port to allow traffic on.
type NodeNetworkPolicyPort struct {
	// The protocol (TCP or UDP) which traffic must match. If not
	// specified, this field defaults to TCP.
	// +kubebuilder:validation:Enum=TCP;UDP
	// +kubebuilder:default=TCP
	// +optional
	Protocol *Protocol `json:"protocol,omitempty"`

	// Port describes a port on the given protocol for a node. If this field is not
	// provided, this matches all port numbers.
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=65535
	// +optional
	Port *int32 `json:"port,omitempty"`
}

// IPBlock describes a particular CIDR that is allowed to the nodes matched by a
// NodeNetworkPolicySpec's nodeSelector. The except entry describes CIDRs that
// should not be included within this rule.
type IPBlock struct {
	// CIDR is a string representing the IP Block
	// Valid examples are "192.168.1.1/24" or "2001:db9::/64"
	// +kubebuilder:validation:Pattern=`^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(/(3[0-2]|2[0-9]|1[0-9]|[0-9]))?$`
	CIDR string `json:"cidr"`
	// Except is a slice of CIDRs that should not be included within an IP Block.
	// Valid examples are "192.168.1.1/24" or "2001:db9::/64".
	// Values will be rejected if they are outside the CIDR range.
	// +optional
	Except []string `json:"except,omitempty"`
}

// +kubebuilder:object:root=true
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// NodeNetworkPolicyList contains a list of NodeNetworkPolicy.
type NodeNetworkPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	// Standard list metadata.
	// More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#metadata
	// +optional
	metav1.ListMeta `json:"metadata,omitempty"`

	// Items is a list of Node Network policies.
	Items []NodeNetworkPolicy `json:"items"`
}
