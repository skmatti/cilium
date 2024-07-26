package v1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName={vmar}
// +kubebuilder:printcolumn:name="Status",type="string",JSONPath=".status.state"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:printcolumn:name="VM",type="string",JSONPath=".spec.vm"
// +kubebuilder:printcolumn:name="User",type="string",JSONPath=".spec.user"
// +kubebuilder:printcolumn:name="TTL",type="string",JSONPath=".spec.ssh.ttl"

// VirtualMachineAccessRequest represents an access request to a vm.
type VirtualMachineAccessRequest struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              VirtualMachineAccessRequestSpec   `json:"spec"`
	Status            VirtualMachineAccessRequestStatus `json:"status,omitempty"`
}

// VirtualMachineAccessRequestSpec holds the spec of the access request.
type VirtualMachineAccessRequestSpec struct {
	// VM is the vm name to access.
	// +kubebuilder:validation:Required
	VM string `json:"vm"`
	// User is the user name used to access the vm.
	// +kubebuilder:validation:Required
	User string `json:"user"`
	// SSH holds the ssh credential used to access the vm.
	// +kubebuilder:validation:Required
	SSH SSHSpec `json:"ssh"`
}

// SSHCredential stores the ssh credential.
type SSHSpec struct {
	// Key is the public key to be programmed for SSH access.
	// +kubebuilder:validation:Required
	Key string `json:"key"`
	// TTL specified how long this key should be valid.
	// +kubebuilder:validation:Required
	TTL metav1.Duration `json:"ttl"`
}

// Shared by both AccessRequest and PasswordResetRequest.
type VirtualMachineAccessRequestState string

const (
	// VMAccessRequestStateConfigured is the VM access request state configured.
	VMAccessRequestStateConfigured VirtualMachineAccessRequestState = "configured"
	// VMAccessRequestStateFailed is the VM access request state failed.
	VMAccessRequestStateFailed VirtualMachineAccessRequestState = "failed"
)

// VirtualMachineAccessRequestStatus describes the status of the VirtualMachineAccessRequest.
type VirtualMachineAccessRequestStatus struct {
	// State of the VirtualMachineAccessRequest.
	// +optional
	State VirtualMachineAccessRequestState `json:"state,omitempty"`
	// Reason for the current status.
	// +optional
	Reason string `json:"reason,omitempty"`
	// Message for any additional message.
	// +optional
	Message string `json:"message,omitempty"`
	// ProcessedAt is the time when the request was processed.
	// +optional
	ProcessedAt metav1.Time `json:"processedAt,omitempty"`
}

// +kubebuilder:object:root=true
// VirtualMachineAccessRequestList contains a list of VirtualMachineAccessRequests.
type VirtualMachineAccessRequestList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []VirtualMachineAccessRequest `json:"items"`
}

func init() {
	SchemeBuilder.Register(&VirtualMachineAccessRequest{}, &VirtualMachineAccessRequestList{})
}
