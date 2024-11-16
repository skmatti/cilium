package v1

import (
	"time" // Do not use pkg/time in test code.

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// VMRuntime specifies configuration for VMRuntime, it includes KubeVirt and CDI.
// +kubebuilder:resource:scope=Cluster
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:printcolumn:name="Enabled",type="string",JSONPath=".spec.enabled"
// +kubebuilder:printcolumn:name="Ready",type="string",JSONPath=".status.ready"
// +kubebuilder:printcolumn:name="PreflightCheck",type="string",JSONPath=".status.preflightCheckSummary.preflightCheckPassed"
type VMRuntime struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	// Spec contains the specification of VMRuntime
	Spec VMRuntimeSpec `json:"spec"`
	// Status holds the current state of the VMRuntime controller
	Status VMRuntimeStatus `json:"status,omitempty"`
}

// VMRuntimeSpec defines desired status of VMRuntime.
type VMRuntimeSpec struct {
	// If Enabled is true, KubeVirt and CDI will be installed, otherwise not.
	// +kubebuilder:validation:Optional
	Enabled *bool `json:"enabled,omitempty"`
	// If useEmulation is enabled, hardware emulation via `/dev/kvm` will not be attempted. QEMU will be used for software emulation instead.
	// It defaults to false if not set
	// +kubebuilder:validation:Optional
	UseEmulation *bool `json:"useEmulation,omitempty"`
	// VMImageFormat decides what is the image format to use to create the virtual machines.
	// The supported format are qcow2 or raw, and default to raw.
	// +kubebuilder:validation:Enum:=raw;qcow2
	VMImageFormat *VMImageFormat `json:"vmImageFormat,omitempty"`
	// EnableGPU indicates if the GPU feature should be enabled or not.
	// When not set, it defaults to false.
	// Optional. Mutable.
	// +kubebuilder:validation:Optional
	EnableGPU *bool `json:"enableGPU,omitempty"`
	// InstallNvidiaDriver indicates if the vmruntime should install the
	// nvidia driver, it is by default false and can be turned on for GDCH
	// product only, for other products, this knob will lead to a failure case
	// as we do not publish the driver container outside of Google.
	// +kubebuilder:validation:Optional
	InstallNvidaDriver *bool `json:"installNvidiaDriver,omitempty"`
	// If CDIUploadProxyVIP is present and DisableCDIUploadProxyVIP is false,
	// the CDI upload proxy service will be exposed as a load balancer with the given VIP.
	// If DisableCDIUploadProxyVIP is true, this field is ignored.
	// By default, CDI upload proxy service will be exposed as a load balancer
	// with an auto-assigned VIP.
	// Optional. Mutable.
	// +kubebuilder:validation:Optional
	CDIUploadProxyVIP *string `json:"cdiUploadProxyVIP,omitempty"`
	// If DisableCDIUploadProxyVIP is true, CDI upload proxy will not be exposed,
	// which means local image upload will not be supported from CLI.
	// Optional. Mutable.
	// Note: this field MUST be set to true when cluster is in manual LoadBalancer mode,
	// or if the cluster LoadBalancer address pool doesn't have extra IPs for the service to use.
	// +kubebuilder:validation:Optional
	DisableCDIUploadProxyVIP *bool `json:"disableCDIUploadProxyVIP,omitempty"`
	// Storage contains global settings for KubeVM storage.
	// Optional. Mutable.
	// +kubebuilder:validation:Optional
	Storage *VMRuntimeStorage `json:"storage,omitempty"`
	// EvictionPolicy contains global configuration to control how virtual
	// machines are evicted during cluster upgrades or node maintenance mode.
	// +kubebuilder:validation:Optional
	EvictionPolicy *VirtualMachineEvictionPolicy `json:"evictionPolicy,omitempty"`
	// DeployOnNestedVirtualization indicates if the cluster is deployed on the nested
	// virtulization environment (e.g. GCE). If it is true, some advanced optimizations
	// will not be configured for Windows VMs.
	// It defaults to false if not set.
	// Optional. Mutable.
	// +kubebuilder:validation:Optional
	DeployOnNestedVirtualization *bool `json:"deployOnNestedVirtualization,omitempty"`
	// AppArmorLauncherProfile indicates the apparmor launcher profile to use for
	// the virt-launcher pod. If the string is empty, there will be no annotation
	// added to the pod.
	// It defaults to an empty string.
	// Optional. Mutable.
	// +kubebuilder:validation:Optional
	AppArmorLauncherProfile *string `json:"appArmorLauncherProfile,omitempty"`
	// FeatureGates is a set of features which have explicitly been disabled or
	// enabled by the user. This state overrides the default state.
	// +kubebuilder:validation:Optional
	FeatureGates map[FeatureGateName]FeatureGateState `json:"featureGates,omitempty"`
}

// GetEvictionPolicy is used to get eviction policy.
func (vr *VMRuntime) GetEvictionPolicy() *VirtualMachineEvictionPolicy {
	if vr.Spec.EvictionPolicy == nil {
		return &VirtualMachineEvictionPolicy{}
	}

	return vr.Spec.EvictionPolicy
}

// VMImageFormat indicates what is the Kubevirt VM image format after import from external sources.
// Detail in here https://qemu.readthedocs.io/en/latest/system/images.html
type VMImageFormat string

const (
	// The qcow2 image format.
	// https://qemu.readthedocs.io/en/latest/system/images.html#cmdoption-image-formats-arg-qcow2
	QCOW2 VMImageFormat = "qcow2"
	// The raw disk format.
	// https://qemu.readthedocs.io/en/latest/system/images.html#cmdoption-image-formats-arg-raw
	RAW VMImageFormat = "raw"
)

// VMImageFormatPointer returns a pointer to a VMImageFormat.
func VMImageFormatPointer(k VMImageFormat) *VMImageFormat {
	return &k
}

// FeatureGateState indicates the state of a feature gate
// +kubebuilder:validation:Enum=Enabled;Disabled
type FeatureGateState string

const (
	// FeatureGateEnabled indicates that the feature gate is enabled.
	FeatureGateEnabled FeatureGateState = "Enabled"
	// FeatureGateDisabled indicates that the feature gate is disabled.
	FeatureGateDisabled FeatureGateState = "Disabled"
)

// FeatureGateName indicates the name of a feature gate
// +kubebuilder:validation:Enum=EjectableCDROMs;VMPersistentState
type FeatureGateName string

const (
	// EjectableCDROMsFeatureGate dictates whether the user can eject and insert
	// cdrom disks on live VirtualMachines.
	EjectableCDROMsFeatureGate FeatureGateName = "EjectableCDROMs"
	// VMStatePersistenceFeatureGate dictates whether VM UEFI and TPM states should
	// be persisted or not. If turned on, a software TPM device will be automatically
	// added to the VMs.
	VMStatePersistenceFeatureGate FeatureGateName = "VMPersistentState"
)

// FeatureStatus is the feature status.
type FeatureStatus struct {
	// Passed field represents the status of the feature
	Passed bool `json:"passed"`

	// FailedNodeNum field represents the number of nodes failed preflight check.
	FailedNodeNum *int `json:"failedNodeNum,omitempty"`
}

// PreflightCheckSummary is the preflight check summary.
type PreflightCheckSummary struct {

	// PreflightCheckName is the name of current vmruntime preflight check CR.
	PreflightCheckName string `json:"preflightCheckName"`

	// PreflightCheckPassed defines the pass result of preflight check
	// PreflightCheckPassed can be nil if there is no preflight check or the
	// preflight check is running.
	// +kubebuilder:validation:Optional
	PreflightCheckPassed *bool `json:"preflightCheckPassed,omitempty"`

	// FeatureStatuses defines the preflight check result of enabled features
	// +kubebuilder:validation:Optional
	FeatureStatuses map[string]FeatureStatus `json:"featureStatuses,omitempty"`
}

// VMRuntimeStatus defines the observed status of VMRuntime.
type VMRuntimeStatus struct {
	// +kubebuilder:default=false
	Ready bool `json:"ready"`

	// PreflightCheckSummary collects the results of vmruntime preflight check.
	// +kubebuilder:validation:Optional
	PreflightCheckSummary *PreflightCheckSummary `json:"preflightCheckSummary,omitempty"`

	// Conditions contain the latest observations of VMRuntime state.
	// Note: cluster-operator maintains its own definition of Conditions
	// (https://source.corp.google.com/cloud-gke/syllogi-baremetal/cluster-operator/api/v1/condition_types.go;l=15?q=condition&ss=piper%2FGoogle%2Fcloud-gke:syllogi-baremetal%2Fcluster-operator%2F).
	// VMRuntime will adopt the open source Kubernetes Conditions
	// (https://pkg.go.dev/k8s.io/apimachinery/pkg/apis/meta/v1#Condition)
	// instead. This is to avoid circular dependencies in the future and
	// keep VMRuntime decoupled from cluster-operator as much as possible.
	// +kubebuilder:validation:Optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
	// Storage contains status information regarding VMRuntime storage.
	// +kubebuilder:validation:Optional
	Storage *VMRuntimeStorageStatus `json:"storage,omitempty"`
	// AnthosBareMetalVersion is the targeted Anthos bare metal version of the cluster.
	// Mutable.
	// +kubebuilder:validation:Optional
	AnthosBareMetalVersion string `json:"anthosBareMetalVersion"`
	// ObservedGeneration contains the object generation when controller sees the object.
	// +kubebuilder:validation:Optional
	ObservedGeneration int64 `json:"observedGeneration"`
	// FeatureGates is a map  of the status for all the feature gates, including
	// both user overridden feature gates and the default feature gates.
	// +kubebuilder:validation:Optional
	FeatureGates map[FeatureGateName]FeatureGateState `json:"featureGates,omitempty"`
}

// IsFeatureGateEnabled is used to decide whether the feature gate is enabled.
func (status *VMRuntimeStatus) IsFeatureGateEnabled(featureGateName FeatureGateName) bool {
	if status.FeatureGates != nil {
		if featureGateState, ok := status.FeatureGates[featureGateName]; ok && featureGateState == FeatureGateEnabled {
			return true
		}
	}

	return false
}

// VMRuntimeStorageStatus contains status information regarding VMRuntime
// storage.
type VMRuntimeStorageStatus struct {
	// DefaultStorageClass is the actual default storage class for
	// VirtualMachineDisks. In order of preference this will be
	// 1) .spec.storage.defaultStorageClass if specified
	// 2) The default Kubernetes cluster storage class if configured
	// 3) Empty
	DefaultStorageClass string `json:"defaultStorageClass,omitempty"`
	// DefaultScratchSpaceStorageClass is the default storage class used for scratch space
	// when importing the VM image. In order of preference this will be
	// 1) .spec.storage.scratchSpaceStorageClass if specified
	// 2) .spec.storage.defaultStorageClass if specified
	// 3) The default Kubernetes cluster storage class if configured
	// 4) Empty
	//
	// The acutal storage class used for scratch space is determined in the following order:
	// 1) .status.storage.defaultScratchSpaceStorageClass if not empty
	// 2) The storage class specified in VirtualMachineDisk.
	// +kubebuilder:validation:Optional
	DefaultScratchSpaceStorageClass string `json:"defaultScratchSpaceStorageClass,omitempty"`
}

// +kubebuilder:object:root=true

// VMRuntimeList contains a list of VMRuntime.
type VMRuntimeList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []VMRuntime `json:"items"`
}

// VMRuntimeStorage contains global settings for KubeVM storage.
type VMRuntimeStorage struct {
	// DefaultStorageClass overrides the Kubernetes default storage class for
	// VM workloads. If this is empty then KubeVM uses the cluster default
	// storage class as the default for VirtualMachineDisks.
	// +kubebuilder:validation:Optional
	DefaultStorageClass string `json:"defaultStorageClass,omitempty"`
	// DefaultScratchSpaceStorageClass specifies the storage class used for
	// scratch space when importing the VM image.
	// +kubebuilder:validation:Optional
	DefaultScratchSpaceStorageClass string `json:"defaultScratchSpaceStorageClass,omitempty"`
}

// VirtualMachineEvictionPolicy contains global configuration to control how
// virtual machines are evicted during cluster upgrades or node maintenance
// mode.
type VirtualMachineEvictionPolicy struct {
	// EvictionStrategy specifies the default strategy for evicting VMs
	// during node maintenance or cluster upgrades. Defaults to LiveMigrate.
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Enum:=LiveMigrate;Restart
	EvictionStrategy EvictionStrategy `json:"evictionStrategy,omitempty"`
	// How many times should the migration of a single VM be attempted before
	// falling back to the EvictionStrategyOnFailedMigration.
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Minimum:=1
	// +kubebuilder:validation:Maximum:=5
	MaxMigrationAttemptsPerVM *int `json:"maxMigrationAttemptsPerVM,omitempty"`
	// MigrationTargetInitializationTimeout specifies a timeout for migration
	// target pod initialization. Amount of time to wait for the target pod to
	// enter the "Running" phase before aborting. Defaults to 90s.
	// +kubebuilder:validation:Optional
	MigrationTargetInitializationTimeout *metav1.Duration `json:"migrationTargetInitializationTimeout,omitempty"`
}

// GetEvictionStrategy is used to get eviction strategy.
func (ep *VirtualMachineEvictionPolicy) GetEvictionStrategy() EvictionStrategy {
	if ep.EvictionStrategy != "" {
		return ep.EvictionStrategy
	}

	return LiveMigrate
}

// GetMaxMigrationAttemptsPerVM is used to get max migration attempts per VM.
func (ep *VirtualMachineEvictionPolicy) GetMaxMigrationAttemptsPerVM() int {
	if ep.MaxMigrationAttemptsPerVM == nil {
		return 3
	}

	return *ep.MaxMigrationAttemptsPerVM
}

// GetMigrationTargetInitializationTimeout is used to get migration target initialization timeout.
func (ep *VirtualMachineEvictionPolicy) GetMigrationTargetInitializationTimeout() metav1.Duration {
	if ep.MigrationTargetInitializationTimeout == nil {
		return metav1.Duration{Duration: time.Second * 90}
	}

	return *ep.MigrationTargetInitializationTimeout
}

// EvictionStrategy
// LiveMigrate: Attempt to migrate migratable workloads by default. Fall back to
//
//	Restart for non-migratable workloads.
//
// Restart:     Restart workloads by default.
type EvictionStrategy string

const (
	// The LiveMigrate eviction strategy.
	LiveMigrate EvictionStrategy = "LiveMigrate"
	// The Restart eviction strategy.
	Restart EvictionStrategy = "Restart"
)

func init() {
	SchemeBuilder.Register(&VMRuntime{}, &VMRuntimeList{})
}
