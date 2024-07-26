package v1

import (
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

//+kubebuilder:object:root=true
//+kubebuilder:resource:scope=Cluster

// VirtualMachineType defines the CPU and Memory resource of a VM.
type VirtualMachineType struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              VirtualMachineTypeSpec `json:"spec"`
}

// VirtualMachineTypeSpec defines the configurations of a virtual machine type.
type VirtualMachineTypeSpec struct {
	CPU    CPU    `json:"cpu"`
	Memory Memory `json:"memory"`
	// Guaranteed indicates if the compute resources of the VMs are in the
	// guaranteed tier. If it is not specified, the resources are in the
	// "efficient" tier. See go/abmvirt-compute for details.
	Guaranteed *bool `json:"guaranteed,omitempty"`
	// GPU specifies the GPU card the VM wants to reserve as a passthrough mode.
	// It is a map of model and quantity, to provide the ability to reserve multiple
	// cards from different models.
	// +kubebuilder:validation:Optional
	GPU *GPUSpec `json:"gpu,omitempty"`
	// AdvancedCompute specifies the advanced compute configurations.
	// +kubebuilder:validation:Optional
	AdvancedCompute *AdvancedCompute `json:"advancedCompute,omitempty"`
}

// Compute specifies the CPU, Memory and VirtualMachineType of a VM.
// CPU and Memory can be defined directly or through VirtualMachineType
// by referencing the VirtualMachineType name.
// VirtualMachineType needs to be predefined by the system or by users.
// Either CPU & Memory or VirtualMachineType needs to be provided.
// It is invalid definition if both of them are provided or not
// provided.
type Compute struct {
	// VirtualMachineTypeName specifies the name of the referenced virtual machine type.
	// It should be an existing virtual machine type.
	VirtualMachineTypeName string `json:"virtualMachineTypeName,omitempty"`
	// vCPUs should be an integer between 1 and 96.
	CPU *CPU `json:"cpu,omitempty"`
	// Memory capacity should be between 1M and 1T.
	Memory *Memory `json:"memory,omitempty"`
	// Guaranteed indicates if the compute resources of the VM are in the
	// guaranteed tier. If it is not specified, the resources are in the
	// "efficient" tier. See go/abmvirt-compute for details.
	Guaranteed *bool `json:"guaranteed,omitempty"`
	// MachineChipSet is the actual chipset of the VirtualMachineInstance.
	// ref: https://wiki.qemu.org/Features/Q35
	// This field is optional.
	MachineChipSet string `json:"machineChipSet,omitempty"`
	// AdvancedCompute specifies the advanced compute configurations.
	// +kubebuilder:validation:Optional
	AdvancedCompute *AdvancedCompute `json:"advancedCompute,omitempty"`
}

// CPU defines CPU.
type CPU struct {
	VCPUs uint32 `json:"vcpus"`
}

// Memory defines memory.
type Memory struct {
	Capacity resource.Quantity `json:"capacity"`
}

// HugePageSize is huge page size.
type HugePageSize string

const (
	// HugePageSize2Mi is huge page size 2Mi.
	HugePageSize2Mi HugePageSize = "2Mi"
	// HugePageSize1Gi is huge page size 1Gi.
	HugePageSize1Gi HugePageSize = "1Gi"
)

// Direct mapping of the OSS NUMAGuestMappingPassthrough, which copies the container passed
// in NUMA topology into VM, aka, VM vNUMA == container_pNUMA.
type NUMAGuestMappingPassthrough struct {
}

// AdvancedCompute defines advanced compute.
type AdvancedCompute struct {
	// DedicatedCPUPlacement indicates that VM should be allocated dedicated host
	// CPU cores and each VM CPU core is pinned to each allocated host CPU core.
	// It can be enabled only when "guaranteed" is set to true.
	// +kubebuilder:validation:Optional
	DedicatedCPUPlacement *bool `json:"dedicatedCPUPlacement,omitempty"`
	// IsolatedEmulatorThread indicates if one more dedicated host CPU core should
	// be allocated to the VM for the QEMU emulator thread. It can be enabled only
	// when DedicatedCPUPlacement is enabled. If not enabled, the emulator thread
	// can run on any allocated host cores.
	// +kubebuilder:validation:Optional
	IsolatedEmulatorThread *bool `json:"isolatedEmulatorThread,omitempty"`
	// Use the huge page instead for the VM memory config. Valid huge pages are
	// 2Mi or 1Gi.
	// note the bug https://github.com/kubernetes-sigs/controller-tools/issues/547
	// +kubebuilder:validation:Enum={"2Mi","1Gi"}
	HugePageSize *HugePageSize `json:"hugePageSize,omitempty"`
	// NUMAGuestMappingPassthrough creates an efficient guest topology based on container
	// NUMA topology.
	// +kubebuilder:validation:Optional
	NUMAGuestMappingPassthrough *NUMAGuestMappingPassthrough `json:"numaGuestMappingPassthrough,omitempty"`
}

// DedicatedCPUPlacementEnabled indicates if DedicatedCPUPlacement is enabled or
// not.
func (a *AdvancedCompute) DedicatedCPUPlacementEnabled() bool {
	return a.DedicatedCPUPlacement != nil && *a.DedicatedCPUPlacement
}

// IsolatedEmulatorThreadEnabled indicates if IsolatedEmulatorThread is enabled
// or not.
func (a *AdvancedCompute) IsolatedEmulatorThreadEnabled() bool {
	return a.IsolatedEmulatorThread != nil && *a.IsolatedEmulatorThread
}

// HugePageSizePointer returns a pointer to a HugePageSize.
func HugePageSizePointer(k HugePageSize) *HugePageSize {
	return &k
}

// +kubebuilder:object:root=true
// VirtualMachineTypeList contains a list of VirtualMachineType.
type VirtualMachineTypeList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []VirtualMachineType `json:"items"`
}

func init() {
	SchemeBuilder.Register(&VirtualMachineType{}, &VirtualMachineTypeList{})
}
