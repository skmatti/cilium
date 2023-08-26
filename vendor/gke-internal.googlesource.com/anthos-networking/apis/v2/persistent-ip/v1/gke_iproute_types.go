package v1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	gatewayv1beta1 "sigs.k8s.io/gateway-api/apis/v1beta1"
)

// ReactionMode is the criteria for choosing matching IPRoute pod.
// +kubebuilder:validation:Enum=ReadyCondition;Exists
type ReactionMode string

// GKEIPRouteSpec defines the desired state of IPRoute.
type GKEIPRouteSpec struct {
	gatewayv1beta1.CommonRouteSpec `json:",inline"`

	// Network defines Pods network interface the prefixes will be attracted to.
	// If not specified, we will use the Primary Network of the Pod.
	//
	// +optional
	// +kubebuilder:default=default
	Network *string `json:"network,omitempty"`

	// PodSelector defines to which Pod the prefixes will be attracted to.
	// When selecting multiple, using the newest Pod that is Ready.
	// Empty selector is not allowed.
	// +kubebuilder:validation:Required
	PodSelector metav1.LabelSelector `json:"podSelector"`

	// ReactionMode defines the criteria for selecting a
	// pod along with the pod selector.
	// Possible values are:
	//	1. ReadyCondition - A pod that has Ready Condition set to true.
	//	2. Exists - A pod whose nodeName is set.
	//
	// +optional
	// +kubebuilder:default=ReadyCondition
	ReactionMode ReactionMode `json:"reactionMode,omitempty"`

	// Prefixes hold a list of all the CIDRs to attract.
	//
	// +kubebuilder:validation:MinItems=1
	Addresses []gatewayv1beta1.GatewayAddress `json:"addresses"`
}

// GKEIPRouteStatus defines the observed state of IPRoute.
type GKEIPRouteStatus struct {
	// Pod holds the name of the Pod the PodSelector specifies.
	// If PodSelector returns multiple items, only the first one is used.
	//
	// +optional
	Pods []string `json:"pods,omitempty"`

	// Conditions describe the current conditions of the IPRoute.
	//
	// Known condition types are:
	//
	// * "Accepted"
	// * "Ready"
	// * "DPv2Ready"
	// * "DPv2Removed"
	//
	// +optional
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status

// GKEIPRoute is the Schema for the iproutes API
type GKEIPRoute struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   GKEIPRouteSpec   `json:"spec,omitempty"`
	Status GKEIPRouteStatus `json:"status,omitempty"`
}

// +genclient
// +genclient:onlyVerbs=get
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:object:root=true

// GKEIPRouteList contains a list of GKEIPRoutes
type GKEIPRouteList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []GKEIPRoute `json:"items"`
}
