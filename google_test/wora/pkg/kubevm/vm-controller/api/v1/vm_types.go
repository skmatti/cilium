package v1

import (
	networkv1 "github.com/GoogleCloudPlatform/gke-networking-api/apis/network/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	virtv1 "kubevirt.io/api/core/v1"
)

const (
	// KubeVMLabel is automatically added to GVM.
	KubeVMLabel = "kubevirt/vm"
)

// VirtualMachineState is virtual machine state.
type VirtualMachineState string

// The valid state of a virtual machine.
// We will inherit the state used by kubevirt as listed here:
// https://github.com/kubevirt/kubevirt/blob/baf3c28abc877a1986e2e08447810ff27f724599/staging/src/kubevirt.io/api/core/v1/types.go#L1230
// State not defined there will be list below.
const (
	Running VirtualMachineState = "Running"
	// Pending means the VirtualMachine is accepted by the system.
	Pending VirtualMachineState = "Pending"
	// ErrorConfiguration means the VirtualMachine has some configuration error.
	// The error could be temporal if it is waiting for dependent resources.
	ErrorConfiguration VirtualMachineState = "ErrorConfiguration"
	// PendingExternalIPAllocation means the VirtualMachine is waiting for an external IPAM to
	// assign an IP to it.
	PendingExternalIPAllocation VirtualMachineState = "PendingExternalIPAllocation"
)

// VirtualMachineRunningState defines the running state of the virtual machine.
// +kubebuilder:validation:Enum=Running;Stopped
type VirtualMachineRunningState string

const (
	// VirtualMachineRunningStateRunning indicates the intention to keep the VM in the running state.
	VirtualMachineRunningStateRunning VirtualMachineRunningState = "Running"
	// VirtualMachineRunningStateStopped indicates the intention to keep the VM in the stopped state.
	VirtualMachineRunningStateStopped VirtualMachineRunningState = "Stopped"
)

// VirtualMachineStateReason is virtual machine state reason.
type VirtualMachineStateReason string

const (
	// NetworkNotFound means the network the vm connects to is not found or is being deleted.
	NetworkNotFound VirtualMachineStateReason = "NetworkNotFound"
	// MachineTypeNotFound means the virtual machine type the vm refers to is not found or is being deleted.
	MachineTypeNotFound VirtualMachineStateReason = "MachineTypeNotFound"
	// MachineDiskNotFound means the virtual machine disk the vm refers to is not found or is being deleted.
	MachineDiskNotFound VirtualMachineStateReason = "MachineDiskNotFound"
	// MachineDiskMisconfig means the virtual machine disk is configured incorrectly.
	MachineDiskMisconfig VirtualMachineStateReason = "MachineDiskMisconfig"
	// InterfaceCreationFailed means the network interface creation failed.
	InterfaceCreationFailed VirtualMachineStateReason = "InterfaceCreationFailed"
	// KubevirtVMCreationFailed means the kubvirt vm creation failed.
	KubevirtVMCreationFailed VirtualMachineStateReason = "KubevirtVMCreationFailed"
	// ReferencedSecretDataNotFound means the secret the vm refers to is not found or does not have the expected key(s) in its data.
	ReferencedSecretDataNotFound VirtualMachineStateReason = "ReferencedSecretDataNotFound"
	// InvalidCloudInitUserdata means the cloud-init userdata is invalid.
	InvalidCloudInitUserdata VirtualMachineStateReason = "InvalidCloudInitUserdata"
)

// OSType is the type of the OS.
// +kubebuilder:validation:Enum=Linux;Windows
type OSType string

const (
	// OSTypeLinux refers to Linux guest os.
	OSTypeLinux OSType = "Linux"
	// OSTypeWindows refers to Windows guest os.
	OSTypeWindows OSType = "Windows"
)

const (
	// ConditionTypeInterfaceCreated means interfaces are created.
	ConditionTypeInterfaceCreated = "InterfaceCreated"
	// ConditionTypeKubevirtVMCreated means kubevirt vm are created.
	ConditionTypeKubevirtVMCreated = "VMCreated"
	// ConditionTypeGuestEnvironmentEnabled means whether guest environment is enabled.
	ConditionTypeGuestEnvironmentEnabled = "GuestEnvironmentEnabled"
	// ConditionTypeGuestEnvironmentSynced means whether guest environment is synced.
	ConditionTypeGuestEnvironmentSynced = "GuestEnvironmentSynced"
	// ConditionTypeRestartingOnConfigurationChange means whether the vm is doing a
	// restart due to configuration change.
	ConditionTypeRestartingOnConfigurationChange = "RestartingOnConfigurationChange"
	// ConditionTypeConfigurationSynced is used to indicate which version configuration is synced to.
	ConditionTypeConfigurationSynced = "ConfigurationSynced"
	// ConditionTypeEditable means whether vm is editable.
	// If AutoRestartOnConfigurationChange is true, editable condition is always true.
	// If AutoRestartOnConfigurationChange is false, editable condition is true when kubevirt vm is not instaniated.
	ConditionTypeEditable = "Editable"

	// Reasons for 'GuestEnvironmentEnabled' condition.
	// ReasonUserConfiguration is the reason for user configuration.
	ReasonUserConfiguration = "UserConfiguration"
	// ReasonMissingOSType is the reason for missing OS type.
	ReasonMissingOSType = "MissingOSType"
	// ReasonNonSupportingOSType is the reason for non supporting OS type.
	ReasonNonSupportingOSType = "NonSupportingOSType"
	// ReasonConfigurationChanged is the reason for configuration changed.
	ReasonConfigurationChanged = "ConfigurationChanged"
	// ReasonConfigurationSynced is the reason for configuration synced.
	ReasonConfigurationSynced = "ConfigurationSynced"

	// Reasons for 'GuestEnvironmentSynced' condition.
	// ReasonGuestEnvironmentNotConnected is the reason for guest environment not connected.
	ReasonGuestEnvironmentNotConnected = "GuestEnvironmentNotConnected"
	// ReasonGuestEnvironmentDataNotFound is the reason for guest environment data not found.
	ReasonGuestEnvironmentDataNotFound = "GuestEnvironmentDataNotFound"
	// ReasonGuestEnvironmentDataProgressing is the reason for guest environment data progressing.
	ReasonGuestEnvironmentDataProgressing = "GuestEnvironmentDataProgressing"
	// ReasonGuestEnvironmentDataSynced is the reason for guest environment data synced.
	ReasonGuestEnvironmentDataSynced = "GuestEnvironmentDataSynced"

	// Reason for 'Editable' condition.
	// ReasonAutoConfigurationPropagationEnabled is the reason for auto configuration propagation enabled.
	ReasonAutoConfigurationPropagationEnabled = "AutoConfigurationPropagationEnabled"
	// ReasonVirtualMachineNotInstantiated is the reason for virtual machine not instantiated.
	ReasonVirtualMachineNotInstantiated = "VirtualMachineNotInstantiated"
	// ReasonVirtualMachineInstantiated is the reason for virtual machine instantiated.
	ReasonVirtualMachineInstantiated = "VirtualMachineInstantiated"
)

// AutoInstallGuestAgentState is the auto install guest agent state.
type AutoInstallGuestAgentState string

const (
	// AutoInstallGuestAgentStateEnabled indicates AutoInstallGuestAgent is enabled.
	AutoInstallGuestAgentStateEnabled AutoInstallGuestAgentState = "Enabled"
	// AutoInstallGuestAgentStateDiasbled indicates AutoInstallGuestAgent is disabled.
	AutoInstallGuestAgentStateDisabled AutoInstallGuestAgentState = "Disabled"
)

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName={gvm}
// +kubebuilder:printcolumn:name="Status",type="string",JSONPath=".status.state"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:printcolumn:name="IP",type=string,JSONPath=`.status.interfaces[0].ipAddresses[0]`

// VirtualMachine is the top-level object for a virtual machine.
type VirtualMachine struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   VirtualMachineSpec   `json:"spec"`
	Status VirtualMachineStatus `json:"status,omitempty"`
}

// VirtualMachineSpec specifies the configuration of a virtual machine.
type VirtualMachineSpec struct {
	// RunningState indicates the desired running state of the VirtualMachine.
	// The field is created mainly for Anthos Config Management use cases.
	// If it is configured, the controller will reconcile the vm to
	// that state. If it is not configured, the controller will fall back
	// to the old behavior, i.e create the vm in running state but allow
	// customers to stop and start it manually though CLI/UI.
	// +kubebuilder:validation:Optional
	RunningState *VirtualMachineRunningState `json:"runningState,omitempty"`
	// AutoRestartOnConfigurationChange specifies whether the controller should
	// automatically restart a vm to pick up configuration changes.
	// The value is defaulted to false.
	// +kubebuilder:validation:Optional
	AutoRestartOnConfigurationChange bool `json:"autoRestartOnConfigurationChange,omitempty"`
	// Interfaces specifies the list of network interfaces in a vm.
	// Multiple interfaces in a vm cannot connect to the same network.
	Interfaces []InterfaceSpec `json:"interfaces"`
	// Compute specifies the CPU, Memory and QEMU machine type of the VM.
	// Users can define CPU and Memory directly or through VirtualMachineType.
	// This field is required.
	// Compute is immutable when the vm is in `Unknown` state.
	// If Compute is updated, the vm needs to restart to make it take effect.
	Compute Compute `json:"compute,omitempty"`
	// Disks specifies the list of disks attached to this vm. If this is
	// specified there must be exactly one boot disk. There must be no
	// intersection between VirtualMachineDiskNames in this list of disk
	// attachments and the names of one of the disks or volumes specified in
	// the virtSpec. Otherwise, this list of disk attachments is additive, it
	// is merged with the disk attachments configured through virtSpec. Changes
	// to disk attachments require a reboot to take effect.
	// +kubebuilder:validation:Optional
	Disks []Disk `json:"disks"`
	// TODO(b/210463981): Make disks optional for backwards compatibility
	//  but add webhook validation if no disks are specified in virtspec also.
	// TODO(b/210542035): The exact one boot disk behavior can change when PXE/network boot is supported.

	// Scheduling specifies the scheduling strategies of this vm.
	// This field is optional, and vm will stick to the default pod scheduling behavior if no strategy specified.
	// Scheduling is immutable when the vm is in `Unknown`, `Starting`, or `Migrating` state.
	// If Scheduling is updated, the vm needs to restart to make it take effect.
	// +kubebuilder:validation:Optional
	Scheduling *Scheduling `json:"scheduling,omitempty"`

	// GuestEnvironment specifies the guest environment configuration of the vm.
	// This field is optional. If the field is nil, we will enable Guest Environment by default.
	// If the field exists but with all nil fields, guest environment will be disabled.
	// Otherwise, the non-nil configuration for each sub-feature inside the structure will
	// override the default configuration of the sub-feature.
	// +kubebuilder:validation:Optional
	GuestEnvironment *GuestEnvironment `json:"guestEnvironment,omitempty"`

	// OSType specifies if the guest vm is Linux or Windows.
	// +kubebuilder:validation:Optional
	OSType OSType `json:"osType,omitempty"`

	// GPU specifies the GPU card the VM wants to reserve as a passthrough mode.
	// It is a map of model and quantity, to provide the ability to reserve multiple
	// cards from different models.
	// +kubebuilder:validation:Optional
	GPU *GPUSpec `json:"gpu,omitempty"`

	// Firmware is the config options for VM initial booting options.
	// +kubebuilder:validation:Optional
	Firmware *Firmware `json:"firmware,omitempty"`

	// CloudInit specifies the cloud-init configuration of the VM.
	// It only takes effect on VMs with cloud-init installed.
	// +kubebuilder:validation:Optional
	CloudInit *CloudInit `json:"cloudInit,omitempty"`

	// StartupScripts specifies the list of startup scripts of the VM.
	// Startup scripts run on every boot.
	// It only takes effect on VMs with cloud-init installed.
	// +kubebuilder:validation:Optional
	StartupScripts []StartupScript `json:"startupScripts,omitempty"`

	// AutoInstallGuestAgent specifies whether we auto install/upgrade the
	// guest agent binary for users when bringing up a VM that has guest
	// environment enabled. The field will be ignored when guest environment
	// is disabled. The default behavior when the field is not configured
	// can vary based on the platform configuration.
	// +kubebuilder:validation:Optional
	AutoInstallGuestAgent *bool `json:"autoInstallGuestAgent,omitempty"`

	// UseVirtioTransitional specifies whether we fall back to legacy virtio 0.9 support if virtio bus is selected on devices.
	// This is helpful for old machines like CentOS6 or RHEL6 which
	// do not understand virtio_non_transitional (virtio 1.0).
	// +kubebuilder:validation:Optional
	UseVirtioTransitional *bool `json:"useVirtioTransitional,omitempty"`
}

// GPUSpec defines the KubeVM GPU request as a model, quantity pair.
type GPUSpec struct {
	// The GPU model the VM want to reserve.
	Model string `json:"model"`
	// The number of GPU card for the specific GPU model the VM want to reserve.
	Quantity uint32 `json:"quantity"`
}

// InterfaceSpec specifies the configuration of a single interface.
// InterfaceSpec is mutable only if a vm doesn't have an active instance.
type InterfaceSpec struct {
	// name should be unique within the interface list of a VirtualMachine.
	Name string `json:"name"`
	// networkInterfaceSpec is the spec of the interface.
	*networkv1.NetworkInterfaceSpec `json:",inline"`
	// Default specifies whether the interface is used for the default route.
	// If the vm has only one interface, this field is optional. If the vm
	// has multiple interfaces, one and only one interface must have the default
	// set to true. This is enforced by webhook.
	// +optional
	Default bool `json:"default,omitempty"`
	// Model specifies the interface model if it is different from the default virtio.
	// It maps to kubevirt model defined here:
	// https://github.com/kubevirt/kubevirt/blob/903a3bd680e8e1b6f3f9448c6168d02ff8e03d6a/staging/src/kubevirt.io/api/core/v1/schema.go#L1122
	// +kubebuilder:validation:Optional
	Model *string `json:"model,omitempty"`
}

// Scheduling defines scheduling.
type Scheduling struct {
	// NodeSelector specifies the node labels that the host node of this vm must have.
	// +optional
	NodeSelector map[string]string `json:"nodeSelector,omitempty"`
	// Affinity specifies the affinity rules of the vm. It includes node affinity and inter-pod affinity/anti-affinity.
	// The vm should obey all specified affinity rules.
	// +optional
	Affinity *corev1.Affinity `json:"affinity,omitempty"`
	// Tolerations allows the vm to schedule onto nodes with matching taints.
	// The vm should obey all specified toleration rules.
	// +optional
	Tolerations []corev1.Toleration `json:"tolerations,omitempty"`
}

// GuestEnvironment specifies configuration of the guest environment.
type GuestEnvironment struct {
	// AccessManagement specifies the access management related configurations.
	// If this field is nil but there is other non-nil fields in GuestEnvironment,
	// access management will be enabled by default.
	// +optional
	AccessManagement *AccessManagementConfig `json:"accessManagement,omitempty"`
}

// Firmware represent the VM initialization options at boot time.
type Firmware struct {
	// UUID reported by the vmi bios.
	// Defaults to a random generated uid.
	// +optional
	UUID *types.UID `json:"uuid,omitempty"`
	// Bootloader represents the initial machine booting options when powering
	// on before loading the kernel. The supported boot options are BIOS or
	// UEFI.
	// +optional
	Bootloader *Bootloader `json:"bootloader,omitempty"`
	// The system-serial-number in SMBIOS
	// +optional
	Serial *string `json:"serial,omitempty"`
}

// Bootloader for the pre OS loading options.
type Bootloader struct {
	// Type can be UEFI or BIOS only as 2 supported booting options.
	// +kubebuilder:validation:Enum:=uefi;bios
	Type string `json:"type"`
	// EnableSecureBoot can be turned on for UEFI bootloader to assist blocking
	// modified or malicious code from loading.
	// Defaults to true
	// +optional
	EnableSecureBoot *bool `json:"enableSecureBoot,omitempty"`
}

// AccessManagementConfig specifies configuration of the AccessManagement feature in the guest environment.
type AccessManagementConfig struct {
	// Enable specifies whether the access management feature should be enabled
	// in the guest environment of the vm.
	// +kubebuilder:validation:Required
	Enable bool `json:"enable"`
}

// CloudInit specifies the cloud-init configuration.
type CloudInit struct {
	// NoCloudSource represents a cloud-init NoCloud source.
	// More info: http://cloudinit.readthedocs.io/en/latest/topics/datasources/nocloud.html
	// +kubebuilder:validation:Optional
	NoCloudSource *virtv1.CloudInitNoCloudSource `json:"noCloud,omitempty"`
}

// StartupScript specifies a startup script.
type StartupScript struct {
	// Name specifies the name of a script.
	// +kubebuilder:validation:Required
	Name string `json:"name"`
	// Script specifies the plain text string of the script.
	// +kubebuilder:validation:Optional
	Script string `json:"script,omitempty"`
	// ScriptBase64 specifies the base64 encoded string of the script.
	// +kubebuilder:validation:Optional
	ScriptBase64 string `json:"scriptBase64,omitempty"`
	// ScriptSecretRef references a k8s secret that contains the script.
	// +kubebuilder:validation:Optional
	ScriptSecretRef *corev1.LocalObjectReference `json:"scriptSecretRef,omitempty"`
}

// VirtualMachineProvisionTime tracks the gvm provision time.
type VirtualMachineProvisionTime struct {
	// The first time of the VM being provisioned, from the object being created
	// till the VM is in running status from control plane perspective.
	InitProvisionTime *metav1.Duration `json:"initProvisionTime,omitempty"`
	// The most recent VM provision time, can be equal to InitProvisionTime if the
	// VM is only being provisioned once, but start diverge if it is being reprovisioned
	// in later stage.
	LastProvisionTime *metav1.Duration `json:"lastProvisionTime,omitempty"`
}

// VirtualMachineStatus describes the status of the virtual machine.
type VirtualMachineStatus struct {
	State               VirtualMachineState                 `json:"state,omitempty"`
	StateTransitionTime map[VirtualMachineState]metav1.Time `json:"stateTransitionTime,omitempty"`
	ProvisionTime       *VirtualMachineProvisionTime        `json:"provisionTime,omitempty"`
	Reason              VirtualMachineStateReason           `json:"reason,omitempty"`
	Message             string                              `json:"message,omitempty"`
	Interfaces          []InterfaceStatus                   `json:"interfaces,omitempty"`
	Conditions          []metav1.Condition                  `json:"conditions,omitempty"`
	// AutoInstallGuestAgent indicates whether AutoInstallGuestAgent is enabled or disabled.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Enum=Enabled;Disabled
	AutoInstallGuestAgent AutoInstallGuestAgentState `json:"autoInstallGuestAgent,omitempty"`
	// Disks holds the status of all disks on the gvm. This is updated based on
	// the disk info in the kvm, such as ejected or inserted cdroms. Disks are in
	// the same list order as on the gvm.
	Disks []DiskStatus `json:"diskStatus,omitempty"`
}

// DiskStatus hold the status of a disk. Currently this is mainly used for the
// the status of inserted or ejected cdroms on the kvm.
type DiskStatus struct {
	VirtualMachineDiskName *string      `json:"virtualMachineDiskName,omitempty"`
	CDRom                  *CDRomStatus `json:"cdrom,omitempty"`
}

// CDRomStatus defines CDRom status.
type CDRomStatus struct {
	Ejected *bool `json:"ejected,omitempty"`
}

// InterfaceStatus describes the interfaces status of the virtual machine.
type InterfaceStatus struct {
	// name is the interface name in the InterfaceSpec.
	Name string `json:"name"`
	// resourceName is the interface CR name.
	ResourceName string `json:"resourceName,omitempty"`
	// networkInterfaceStatus is the status of the interface.
	*networkv1.NetworkInterfaceStatus `json:",inline"`
}

// +kubebuilder:object:root=true

// VirtualMachineList contains a list of VirtualMachines.
type VirtualMachineList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []VirtualMachine `json:"items"`
}

func init() {
	SchemeBuilder.Register(&VirtualMachine{}, &VirtualMachineList{})
}
