// All fields in this package are required unless Explicitly marked optional
// +kubebuilder:validation:Required
package v1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// TrafficSelectorSpec defines the desired state of TrafficSelector
// Exactly one of {`Ingress`, `Egress`} pointers should be set.
type TrafficSelectorSpec struct {
	// ServiceFunctionChain defines the service chain where selected traffic should be sent.
	// +kubebuilder:validation:MinLength=1
	ServiceFunctionChain string `json:"serviceFunctionChain"`
	// Subject defines what objects the TrafficSelector applies to.
	Subject TrafficSelectorSubject `json:"subject"`
	// Ingress rule to be applied to the selected objects with subject as the frame of reference
	// +optional
	Ingress *TrafficSelectorIngressRule `json:"ingress,omitempty"`
	// Egress rule to be applied to the selected objects with subject as the frame of reference.
	// +optional
	Egress *TrafficSelectorEgressRule `json:"egress,omitempty"`
}

// TrafficSelectorStatus defines the observed state of TrafficSelector
type TrafficSelectorStatus struct {
}

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status
//+kubebuilder:resource:scope=Cluster

// TrafficSelector is the Schema for the trafficselectors API
type TrafficSelector struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   TrafficSelectorSpec   `json:"spec"`
	Status TrafficSelectorStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// TrafficSelectorList contains a list of TrafficSelector
type TrafficSelectorList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []TrafficSelector `json:"items"`
}

// Exactly one of {`Pods`} pointers should be set.
type TrafficSelectorSubject struct {
	// Network specifies to which network interfaces this TrafficSelector applies. All service
	// functions in the referenced service chain must belong to the same network as the
	// TrafficSelector to maintain network isolation. The default pod network is chosen if not
	// present.
	// +optional
	Network string `json:"network,omitempty"`
	// Allows the user to select a given set of pod(s) in selected namespace(s).
	Pods NamespacedPodsSubject `json:"pods"`
}

type NamespacedPodsSubject struct {
	// This field follows standard label selector semantics. If empty, it selects all Namespaces.
	NamespaceSelector metav1.LabelSelector `json:"namespaceSelector"`
	// Used to explicitly select pods within a namespace; if empty, it selects all Pods.
	PodSelector metav1.LabelSelector `json:"podSelector"`
}

// +kubebuilder:validation:MinProperties=1
type TrafficSelectorIngressRule struct {
	// Source peer from which traffic will be steered by this TrafficSelector.
	// If this field is not present or empty, this rule matches all source IPs.
	// +optional
	From *TrafficSelectorPeer `json:"from,omitempty"`
	// Ports allows for matching traffic based on port and protocols.
	// If Ports is not set then the rule does not filter traffic via port.
	// However, this is not currently supported and Ports (with at least 1 item) is required.
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=10
	Ports []TrafficSelectorPort `json:"ports,omitempty"`
}

// +kubebuilder:validation:MinProperties=1
type TrafficSelectorEgressRule struct {
	// Destination peer from which traffic will be steered by this TrafficSelector.
	// If this field is not present or empty, this rule matches all destination IPs.
	// +optional
	To *TrafficSelectorPeer `json:"to,omitempty"`
	// Ports allows for matching traffic based on port and protocols.
	// If Ports is not set then the rule does not filter traffic via port.
	// However, this is not currently supported and Ports (with at least 1 item) is required.
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=10
	Ports []TrafficSelectorPort `json:"ports,omitempty"`
}

// +kubebuilder:validation:MinProperties=1
// +kubebuilder:validation:MaxProperties=1
type TrafficSelectorPeer struct {
	// IPBlock selects IP CIDR ranges.
	// +optional
	IPBlock *TrafficSelectorIPBlock `json:"ipBlock,omitempty"`
}

type TrafficSelectorIPBlock struct {
	// CIDR is a string representing the IP Block (e.g. "192.168.1.1/24", "2001:db9::/64").
	// +kubebuilder:validation:MinLength=1
	CIDR string `json:"cidr"`
}

// TrafficSelectorPort describes how to select network ports on pod(s).
// +kubebuilder:validation:MinProperties=1
// +kubebuilder:validation:MaxProperties=1
type TrafficSelectorPort struct {
	// Port selects a port on a pod(s) based on number.
	// +optional
	PortNumber *Port `json:"portNumber,omitempty"`
	// AllPorts selects all ports.
	// +optional
	AllPorts *AllPorts `json:"allPorts,omitempty"`
}

type Port struct {
	// Protocol is the network protocol (TCP, UDP) which traffic must match.
	// If not specified, this field defaults to TCP.
	// +optional
	// +kubebuilder:default:=TCP
	Protocol TrafficSelectorProtocol `json:"protocol"`
	// Number defines a network port value.
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	Port int32 `json:"port"`
}

type AllPorts struct {
	// Protocol is the network protocol (TCP, UDP) which traffic must match.
	// If not specified, this field defaults to TCP.
	// +optional
	// +kubebuilder:default:=TCP
	Protocol TrafficSelectorProtocol `json:"protocol"`
}

// +kubebuilder:validation:Enum=UDP;TCP
type TrafficSelectorProtocol string
