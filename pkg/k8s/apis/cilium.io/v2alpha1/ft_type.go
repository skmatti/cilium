package v2alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// FlowTagger defines the Schema for the `FlowTagger` API.
//
// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:categories={cilium},scope=Cluster,shortName={ft,fts}
// +kubebuilder:object:root=true
// +kubebuilder:storageversion
// +kubebuilder:subresource:status
type FlowTagger struct {
	// +deepequal-gen=false
	metav1.TypeMeta `json:",inline"`
	// +deepequal-gen=false
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// Spec is the desired configuration for flow tagger resource.
	Spec FlowTaggerSpec `json:"spec,omitempty"`

	// Status for the flow tagger.
	Status FlowTaggerStatus `json:"status,omitempty"`
}

// FlowTaggerSpec defines the specification or expected state of the `FlowTagger` resource.
type FlowTaggerSpec struct {
	// Source for the flow tagger.
	// +kubebuilder:validation:Optional
	Source FlowTaggerEntity `json:"source,omitempty"`

	// Destination for the flow tagger.
	// +kubebuilder:validation:Optional
	Destination FlowTaggerEntity `json:"destination,omitempty"`

	// Protocol for the flow tagger.
	// If not specified, it defaults to ALL.
	// +kubebuilder:validation:Optional
	// +kubebuilder:default:=ALL
	// +kubebuilder:validation:Enum=TCP;UDP;ALL
	Protocol FlowTaggerProtocol `json:"protocol,omitempty"`

	// Trace ID.
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	// +kubebuilder:validation:Required
	TraceID int32 `json:"traceID" valid:"required"`
}

// FlowTaggerProtocol defines the protocol for the flow tagger.
type FlowTaggerProtocol string

const (
	// FlowTaggerProtocolTCP is for TCP protocol.
	FlowTaggerProtocolTCP FlowTaggerProtocol = "TCP"
	// FlowTaggerProtocolUDP is for UDP protocol.
	FlowTaggerProtocolUDP FlowTaggerProtocol = "UDP"
	// FlowTaggerProtocolALL is for all protocols.
	FlowTaggerProtocolALL FlowTaggerProtocol = "ALL"
)

// FlowTaggerEntity defines the properties of the flow tagger entity either source or destination.
type FlowTaggerEntity struct {
	// IP address assigned to flow tagger entity.
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Format=ip
	IP string `json:"ip,omitempty"`

	// Port number.
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=65535
	// +kubebuilder:validation:Optional
	Port uint16 `json:"port,omitempty"`
}

// FlowTaggerStatus defines the observed state of the `FlowTagger` resource.
type FlowTaggerStatus struct {
	// Condition represents the latest updated observation of the FlowTagger's state.
	// +deepequal-gen=false
	Conditions []metav1.Condition `json:"condition,omitempty"`
}

// FlowTaggerList Contains a list of `FlowTagger` objects.
//
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +k8s:openapi-gen=false
// +deepequal-gen=false
type FlowTaggerList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`

	// Items is a list of FlowTagger resources.
	Items []FlowTagger `json:"items"`
}
