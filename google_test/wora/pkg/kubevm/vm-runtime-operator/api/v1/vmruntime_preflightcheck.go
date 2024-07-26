package v1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// CheckResult is the detailed results for a feature.
type CheckResult struct {
	// CheckName indicates check item name. E.g. CheckName KVM indicates it checks kvm exist in the node.
	CheckName string `json:"checkName"`
	// Passed indicates the result of the check.
	Passed bool `json:"passed"`
	// Message indicates the output of the check command. If the check passed, there will be no message.
	Message *string `json:"message,omitempty"`
}

// NodeResult indicates all check results on the same node.
type NodeResult struct {
	// Passed specifies whether the node check succeeded.
	Passed bool `json:"passed"`
	// Results is a list of detailed check results for features.
	// +kubebuilder:validation:Optional
	Results []CheckResult `json:"results,omitempty"`
}

// FailureResult is the result of failed vmruntime preflight check on the same node.
type FailureResult struct {
	// Results is a list of detailed check results for failed features.
	Results []CheckResult `json:"results,omitempty"`
}

// VMRuntimePreflightCheckSpec is the VM runtime preflight check spec.
type VMRuntimePreflightCheckSpec struct {
}

// VMRuntimePreflightCheckStatus contains all vmruntime preflight check results.
type VMRuntimePreflightCheckStatus struct {
	// Pass specifies whether the check succeeded, this filed will be populated
	// after all the check has finished.
	// +kubebuilder:validation:Optional
	Pass *bool `json:"pass,omitempty"`

	// Checks indicates check results of all nodes.
	// The structure is a map of node names as keys and check results as values.
	// +kubebuilder:validation:Optional
	Checks map[string]NodeResult `json:"checks,omitempty"`

	// Failures indicates failed results of failed nodes.
	// The structure is a map of node names as keys and failed check results as values.
	// Quantity limit of the number of failures is 10.
	// +kubebuilder:validation:optional
	Failures map[string]FailureResult `json:"failures,omitempty"`

	// Represents time when the check was acknowledged by the check controller.
	// +kubebuilder:validation:optional
	StartTime *metav1.Time `json:"startTime,omitempty"`

	// Represents time when the check was completed.
	// +kubebuilder:validation:optional
	CompletionTime *metav1.Time `json:"completionTime,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Pass",type="boolean",JSONPath=".status.pass",description="VMRuntimePreflightCheck run result"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp",description="CreationTimestamp is a timestamp representing the server time when this object was created. It is not guaranteed to be set in happens-before order across separate operations. Clients may not set this value. It is represented in RFC3339 form and is in UTC."
// +kubebuilder:resource:shortName={vmruntimepfc}

// VMRuntimePreflightCheck is the Schema for VMRuntimePreflightCheck API.
type VMRuntimePreflightCheck struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   VMRuntimePreflightCheckSpec   `json:"spec,omitempty"`
	Status VMRuntimePreflightCheckStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// VMRuntimePreflightCheckList contains a list of VMRuntimePreflightCheck.
type VMRuntimePreflightCheckList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []VMRuntimePreflightCheck `json:"items"`
}

func init() {
	SchemeBuilder.Register(&VMRuntimePreflightCheck{}, &VMRuntimePreflightCheckList{})
}
