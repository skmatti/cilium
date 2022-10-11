// All fields in this package are required unless Explicitly marked optional
// +kubebuilder:validation:Required
package v1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ServiceFunctionChainSpec defines the desired state of ServiceFunctionChain
type ServiceFunctionChainSpec struct {
	// sessionAffinity specifies the session affinity behavior for all service functions in the ServiceFunctionChain.
	// Nil pointer represents disabled session affinity.
	// +optional
	SessionAffinity *ServiceFunctionSessionAffinity `json:"sessionAffinity,omitempty"`
	// internalTrafficPolicy describes how traffic is forwarded to service function pods.
	// The only currently supported value is "Cluster", in which case traffic is forwarded to all service function pods evenly.
	// +optional
	// +kubebuilder:default:=Cluster
	InternalTrafficPolicy ServiceInternalTrafficPolicyType `json:"internalTrafficPolicy,omitempty"`
	// List of service functions that selected traffic must be steered through.
	// +kubebuilder:validation:MinItems:=1
	// +kubebuilder:validation:MaxItems:=1
	ServiceFunctions []ServiceFunction `json:"serviceFunctions"`
}

// ServiceFunctionChainStatus defines the observed state of ServiceFunctionChain
type ServiceFunctionChainStatus struct {
	// servicePathId is a unique identifier that's automatically assigned.
	// It's used as a tiebreaker in determining precedence between conflicting traffic selectors.
	// +optional
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=16777215
	ServicePathId *int32 `json:"servicePathId,omitempty"`
}

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status
//+kubebuilder:resource:scope=Cluster

// ServiceFunctionChain is the Schema for the servicefunctionchains API
type ServiceFunctionChain struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   ServiceFunctionChainSpec   `json:"spec"`
	Status ServiceFunctionChainStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// ServiceFunctionChainList contains a list of ServiceFunctionChain
type ServiceFunctionChainList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ServiceFunctionChain `json:"items"`
}

// Exactly one of {`ClientIPNoDestination`} pointers should be set.
// +kubebuilder:validation:MinProperties=1
// +kubebuilder:validation:MaxProperties=1
type ServiceFunctionSessionAffinity struct {
	// Session affinity based on 1-tuple hash created from the source IP address.
	// +optional
	ClientIPNoDestination *ClientIPNoDestinationConfig `json:"clientIPNoDestination,omitempty"`
}

type ClientIPNoDestinationConfig struct {
	// timeoutSeconds specifies the seconds of session sticky time.
	// The value must be >0 && <=86400(for 1 day).
	// Default value is 10800(for 3 hours).
	// +optional
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=86400
	// +kubebuilder:default:=10800
	TimeoutSeconds int32 `json:"timeoutSeconds"`
}

// +kubebuilder:validation:Enum=Cluster
type ServiceInternalTrafficPolicyType string

const (
	InternalTrafficPolicyCluster = "Cluster"
)

type ServiceFunction struct {
	// Name of the service function. It must be a valid RFC 1035 label.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=63
	// +kubebuilder:validation:Pattern=`^[a-z]([-a-z0-9]*[a-z0-9])?$`
	Name string `json:"name"`
	// Namespace containing the service function pods. It must be a valid RFC 1123 label.
	// +kubebuilder:validation:MinLength=1
	Namespace string `json:"namespace"`
	// Route service function traffic to pods matching this selector.
	PodSelector ServiceLabelSelector `json:"podSelector"`
}

// ServiceLabelSelector is an internal representation of the older style of label selectors
// that doesn't support expressions.
// +structType=atomic
type ServiceLabelSelector struct {
	// matchLabels is a map of {key,value} pairs.
	// +kubebuilder:validation:MinProperties:=1
	MatchLabels map[string]string `json:"matchLabels"`
}
