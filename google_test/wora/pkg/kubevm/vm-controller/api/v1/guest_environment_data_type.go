package v1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// GuestEnvironmentDataResourceName is the guest environment data resource name.
const GuestEnvironmentDataResourceName = "guestenvironmentdata"

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName={ged}
// +kubebuilder:printcolumn:name="Status",type="string",JSONPath=".status.state"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:printcolumn:name="Access-Management",type="string",JSONPath=".status.accessManagement.state"

// GuestEnvironmentData defines the guest environment data.
type GuestEnvironmentData struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              GuestEnvironmentDataSpec   `json:"spec"`
	Status            GuestEnvironmentDataStatus `json:"status,omitempty"`
}

// GuestEnvironmentDataSpec holds the data needed by the guest agent of a vm.
type GuestEnvironmentDataSpec struct {
	// AccessManagement holds the access management related data.
	// +kubebuilder:validation:Required
	AccessManagement AccessManagementData `json:"accessManagement"`
}

// AccessManagementData stores the information related to AccessManagement.
type AccessManagementData struct {
	// Enable tells whether the guest agent should enable the access management.
	// When managed is changed from true to false, we will remove all existing
	// google programmed SSH keys.
	// +kubebuilder:validation:Required
	Enable bool `json:"enable"`
	// AccessRequests stores the access requests to be programmed on the guest.
	// +optional
	AccessRequests []AccessRequest `json:"accessRequests,omitempty"`
	// PasswordResetRequests stores the password reset requests to be processed on the guest.
	// +optional
	PasswordResetRequests []PasswordResetRequest `json:"passwordResetRequests,omitempty"`
}

// AccessRequest stores the information of a VirtualMachineAccessRequest.
type AccessRequest struct {
	// Name is the name of the VirtualMachineAccessRequest.
	// +kubebuilder:validation:Required
	Name string `json:"name"`
	// Key is the SSH key requested by the VirtualMachineAccessRequest with the expiration information.
	// +kubebuilder:validation:Required
	Key string `json:"key"`
}

// PasswordResetRequest stores the information of a VirtualMachinePasswordResetRequest.
type PasswordResetRequest struct {
	// Name is the name of the VirtualMachinePasswordResetRequest.
	// +kubebuilder:validation:Required
	Name string `json:"name"`
	// Key is the user and the encryption information for the reset requested by the VirtualMachinePasswordResetRequest.
	// +kubebuilder:validation:Required
	EncryptKey string `json:"encryptKey"`
}

// GuestEnvironmentDataState is the guest environment data state.
type GuestEnvironmentDataState string

const (
	// GuestEnvironmentDataStateSynced is the guest environment data state synced.
	GuestEnvironmentDataStateSynced GuestEnvironmentDataState = "Synced"
)

// GuestEnvironmentDataStatus describes the status of the guest environment.
type GuestEnvironmentDataStatus struct {
	// State of the guest environment data, i.e synced or out of sync.
	// +optional
	State GuestEnvironmentDataState `json:"state,omitempty"`
	// Reason for the current status.
	// +optional
	Reason string `json:"reason,omitempty"`
	// Message for any additional message.
	// +optional
	Message string `json:"message,omitempty"`
	// ObservedGeneration is the configuration generation guest agent observed.
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`
	// LastConnectTime represents the last time agent updated the status.
	// This can work as a heartbeat to indicate the guest environment aliveness.
	LastConnectTime metav1.Time `json:"lastConnectTime,omitempty"`
	// GuestEnvironmentVersion shows the version of the guest agent
	// running on the guest vm.
	GuestEnvironmentVersion string `json:"guestEnvironmentVersion,omitempty"`
	// AccessManagement shows the status of the access manager
	// inside the guest agent running on the guest vm.
	AccessManagement *AccessManagementStatus `json:"accessManagement,omitempty"`
}

// AccessManagementState is the access management state.
type AccessManagementState string

const (
	// AccessManagementStateReady is the access management ready state.
	AccessManagementStateReady AccessManagementState = "Ready"
	// AccessManagementStateNotReady is the access management not ready state.
	AccessManagementStateNotReady AccessManagementState = "NotReady"
	// AccessManagementStateDisabled is the access management disabled state.
	AccessManagementStateDisabled AccessManagementState = "Disabled"
)

// AccessManagementStatus defines access management status.
type AccessManagementStatus struct {
	// State of the access manager in the guest agent.
	// +optional
	State AccessManagementState `json:"state,omitempty"`
	// Reason for the current status.
	// +optional
	Reason string `json:"reason,omitempty"`
	// Message for any additional message.
	// +optional
	Message string `json:"message,omitempty"`
	// Status of the access requests.
	AccessRequests []AccessRequestStatus `json:"accessRequests,omitempty"`
	// Status of the password reset requests.
	PasswordResetRequests []PasswordResetRequestStatus `json:"passwordResetRequests,omitempty"`
}

// AccessRequestStatus holds the status of the access requests.
type AccessRequestStatus struct {
	// Name is the name of the VirtualMachineAccessRequest.
	// +kubebuilder:validation:Required
	Name string `json:"name"`
	// VirtualMachineAccessRequestStatus is the status of the request.
	*VirtualMachineAccessRequestStatus `json:",inline"`
}

// PasswordResetRequestStatus holds the status of the password reset requests.
type PasswordResetRequestStatus struct {
	// Name is the name of the VirtualMachinePasswordResetRequest.
	// +kubebuilder:validation:Required
	Name string `json:"name"`
	// VirtualMachinePasswordResetRequestStatus is the status of the request.
	*VirtualMachinePasswordResetRequestStatus `json:",inline"`
}

// +kubebuilder:object:root=true
// GuestEnvironmentDataList contains a list of GuestEnvironmentData.
type GuestEnvironmentDataList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []GuestEnvironmentData `json:"items"`
}

func init() {
	SchemeBuilder.Register(&GuestEnvironmentData{}, &GuestEnvironmentDataList{})
}
