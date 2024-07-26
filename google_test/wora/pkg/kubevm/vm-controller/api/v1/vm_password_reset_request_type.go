package v1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName={vmprr}
// +kubebuilder:printcolumn:name="Status",type="string",JSONPath=".status.state"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:printcolumn:name="VM",type="string",JSONPath=".spec.vm"
// +kubebuilder:printcolumn:name="User",type="string",JSONPath=".spec.user"

// VirtualMachinePasswordResetRequest represents an password reset request to a vm.
type VirtualMachinePasswordResetRequest struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              VirtualMachinePasswordResetRequestSpec   `json:"spec"`
	Status            VirtualMachinePasswordResetRequestStatus `json:"status,omitempty"`
}

// VirtualMachinePasswordResetRequestSpec holds the spec of the password reset request.
type VirtualMachinePasswordResetRequestSpec struct {
	// VM is the vm name to PasswordReset.
	// +kubebuilder:validation:Required
	VM string `json:"vm"`
	// User is the user name used to PasswordReset the vm.
	// +kubebuilder:validation:Required
	User string `json:"user"`
	// PublicKey stores the public key info to encrypt the password.
	// +kubebuilder:validation:Required
	PublicKey PublicKey `json:"publicKey"`
}

// PublicKey stores the public key info to encrypt the password.
// A private key can be created with rsa.GenerateKey, the PublicKey with exponent and modulus is a member of the private key.
// To get the base64 representation of a big.Int (like exponent or modulus), use base64.StdEncoding.EncodeToString(i.Bytes()).
type PublicKey struct {
	// Exponent is the base64 encoding of the public key exponent bytes
	// +kubebuilder:validation:Required
	Exponent string `json:"exponent"`
	// Modulus is the base64 encoding of the public key modulus bytes
	// +kubebuilder:validation:Required
	Modulus string `json:"modulus"`
}

// VirtualMachinePasswordResetRequestStatus describes the status of the VirtualMachinePasswordResetRequest.
// The password can be converted to bytes with base64.StdEncoding.DecodeString, and decrypted with rsa.DecryptOAEP(sha1.New(), rand.Reader, privKey, passBytes, nil).
type VirtualMachinePasswordResetRequestStatus struct {
	// State of the VirtualMachinePasswordResetRequest.
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
	// EncryptedPassword is the new password for the user specified in the request.
	// +optional
	EncryptedPassword string `json:"encryptedPassword,omitempty"`
}

// +kubebuilder:object:root=true
// VirtualMachinePasswordResetRequestList contains a list of VirtualMachinePasswordResetRequests.
type VirtualMachinePasswordResetRequestList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []VirtualMachinePasswordResetRequest `json:"items"`
}

func init() {
	SchemeBuilder.Register(&VirtualMachinePasswordResetRequest{}, &VirtualMachinePasswordResetRequestList{})
}
