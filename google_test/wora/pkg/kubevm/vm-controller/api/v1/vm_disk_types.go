package v1

import (
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	cdiv1 "kubevirt.io/containerized-data-importer-api/pkg/apis/core/v1beta1"
)

const (
	// ConditionTypeVirtualMachineDiskReady indicates whether or not a
	// VirtualMachineDisk has been provisioned and is ready for consumption.
	ConditionTypeVirtualMachineDiskReady = "Ready"
	// ConditionTypVirtualMachineDiskResizeInProgress indicates whether or not a
	// VirtualMachineDisk is in the progress of resizing.
	ConditionTypVirtualMachineDiskResizeInProgress = "ResizeInProgress"

	// Reasons for 'ResizeInProgress' condition.
	// ReasonPVCResizing defines the reason for PVC resizing.
	ReasonPVCResizing = "PVCResizing"
	// ReasonPVCResizePending defines the reason for PVC resize pending.
	ReasonPVCResizePending = "PVCResizePending"
)

// +kubebuilder:validation:Enum:=virtio;sata;scsi
type DiskDriver string

const (
	// DiskDriverVirtio virtio disk driver.
	// virtio has the best performance but requires guest VirtualMachine to have virtio drivers enabled.
	DiskDriverVirtio DiskDriver = "virtio"
	// DiskDriverSata sata disk driver.
	// If the guest VirtualMachine requires the disk to be exposed via sata interface.
	// sata is slower than virtio but works for most guest VirtualMachine without additional drivers.
	DiskDriverSata DiskDriver = "sata"
	// DiskDriverSCSI SCSI disk driver.
	// If the guest VirtualMachine requires the disk to be exposed via scsi interface.
	// scsi is slower than virtio but works for most guests VirtualMachine without additional drivers.
	DiskDriverSCSI DiskDriver = "scsi"
)

// DiskType is the type of the disk.
// +kubebuilder:validation:Enum=cdrom;
type DiskType string

const (
	// Deprecated, use CDRom: {} within the GVM disk spec itself.
	// DiskTypeCDRom means the disk should be treated as a cdrom.
	DiskTypeCDRom DiskType = "cdrom"
)

// Disk represents the attachment relationship between the VirtualMachine and the
// VirtualMachineDisk. Priority is given to disks and volumes in the passthrough
// virtSpec; disk attachments whose VirtualMachineDiskName conflict the name of
// one of the disks or volumes specified in the virtSpec will be skipped (not
// attached).
type Disk struct {
	// ReadOnly specifies the read/write capability enforced.
	// When set to false, the disk supports both read and write.
	// When set to true, the disk supports only reads.
	// +kubebuilder:validation:Optional
	ReadOnly bool `json:"readOnly,omitempty"`
	// Boot specifies whether this disk is the boot device for the VirtualMachine.
	// There must be exactly one disk marked as boot.
	// +kubebuilder:validation:Optional
	Boot bool `json:"boot,omitempty"`
	// AutoDelete specifies whether the disk should be deleted when the VirtualMachine is deleted.
	// AutoDelete only applies while a disk is attached to a VirtualMachine. A
	// VirtualMachineDisk's lifecycle is decoupled from the VirtualMachine once
	// it is no longer referenced in .spec.disks
	// +kubebuilder:validation:Optional
	AutoDelete bool `json:"autoDelete,omitempty"`
	// VirtualMachineDiskName refers to an VirtualMachineDisk in the same namespace.
	// This field is required.
	// +kubebuilder:validation:Optional
	VirtualMachineDiskName string `json:"virtualMachineDiskName,omitempty"`
	// Driver used to attach the disk
	// Default: virtio
	// +kubebuilder:validation:Optional
	Driver DiskDriver `json:"driver,omitempty"`
	// CDRom is used to denote that this disk is of type cdrom. Additional
	// specifications can be found in the CDRom struct that are only relevant to
	// CDRom disks.
	// +kubebuilder:validation:Optional
	CDRom *CDRom `json:"cdrom,omitempty"`
}

// CDRom is used to denote that this disk is of type cdrom. Additional
// specifications can be found in the CDRom struct that are only relevant to
// CDRom disks.
type CDRom struct {
	// Ejected denotes if the CDRom is Ejected. This creates an open CDRom slot
	// which can later be used to insert CDRoms into a live vm.
	Ejected bool `json:"ejected,omitempty"`
}

// DataVolumeSourceDisk provides the parameters to create a data volume from an existing disk.
type DataVolumeSourceDisk struct {
	// The name of the source disk
	Name string `json:"name"`
}

// DiskSource is used to specify exactly one of the supported sources to populate a disk from.
type DiskSource struct {
	// HTTP denotes the disk contents are from a http(s) server accessible by a URL.
	// Optionally basic auth and custom CA can be specified along with the URL.
	HTTP *cdiv1.DataVolumeSourceHTTP `json:"http,omitempty"`
	// GCS denotes the disk contents are from a GCS bucket.
	GCS *cdiv1.DataVolumeSourceGCS `json:"gcs,omitempty"`
	// S3 denotes the disk contents are from a S3 bucket.
	S3 *cdiv1.DataVolumeSourceS3 `json:"s3,omitempty"`
	// Registry denotes the disk contents are from an image registry.
	Registry *cdiv1.DataVolumeSourceRegistry `json:"registry,omitempty"`
	// Disk denotes the disk contents are from a virtual machine disk.
	Disk *DataVolumeSourceDisk `json:"virtualMachineDisk,omitempty"`
}

// VirtualMachineDiskPhase is the virtual machine disk phase.
type VirtualMachineDiskPhase string

const (
	// Disk waiting for provisioning.
	DiskPhasePending VirtualMachineDiskPhase = "Pending"
	// Disk configuration has error.
	DiskPhaseErrorConfiguration VirtualMachineDiskPhase = "ErrorConfiguration"
	// Disk succeeded.
	DiskPhaseSucceeded VirtualMachineDiskPhase = "Succeeded"
)

// HasPVCReference is used to verify whether virtual machine disk has PVC reference.
func (d *VirtualMachineDisk) HasPVCReference() bool {
	return d.Spec.PersistentVolumeClaimName != nil
}

// VirtualMachineDiskSpec defines the desired state of VirtualMachineDisk.
type VirtualMachineDiskSpec struct {
	// Source specifies the source from which the disk contents are populated. If
	// this field is omitted a blank disk will be provisioned.
	// +kubebuilder:validation:Optional
	Source *DiskSource `json:"source,omitempty"`
	// Size is the size of the disk (5GiB, 600MiB, etc.)
	// If the source is an existing PVC, the size is ignored.
	// For all other sources size must be provided.
	// +kubebuilder:validation:Optional
	Size resource.Quantity `json:"size"`
	// StorageClassName specifies the Kubernetes storage class to use while
	// provisioning a VirtualMachineDisk's backing PersistentVolumeClaim.
	// If the sources is an existing PVC, StorageClassName is irrelevant,
	// as no new PVC is provisioned.
	// Default: use default storage class if unspecified.
	// +kubebuilder:validation:Optional
	StorageClassName string `json:"storageClassName,omitempty"`
	// persistentVolumeClaimName denotes the disk contents are from an existing PVC
	// in the same namespace. The provided PVC is used as is and there is no cloning.
	// The corresponding PV should contain a 'disk.img' on the root path of the
	// filesystem which is the data for the vm disk. Based on the disk contents
	// it can be used as a boot or additional disk.
	// Refer https://kubevirt.io/user-guide/virtual_machines/disks_and_volumes/#persistentvolumeclaim
	// for more details.
	// If this field is set, the source field becomes irrelevant.
	PersistentVolumeClaimName *string `json:"persistentVolumeClaimName,omitempty"`
	// DiskType specifies the type of the disk if it needs be treated differently.
	// Currently supported value is cdrom.
	// This field is mutable.
	// +kubebuilder:validation:Optional
	DiskType *DiskType `json:"diskType,omitempty"`
}

// VirtualMachineDiskProvisionTime tracks the gdisk provision time.
type VirtualMachineDiskProvisionTime struct {
	// ProvisionTime tracks the gdisk provision time, if the source is based on
	// DV, it tracks the time from initialization till DV reports ready, if the
	// source is PVC, it tracks the time from initialization till the gDisk successfully
	// bind the PVC to the DV, for instance, if the PVC is already in a ready status
	// with disk provisioned inside, this time is almost negligible, but if the gDisk
	// is linking to a PVC that is still undergoing disk import, this time will track such
	// import disk into PV duration.
	ProvisionTime *metav1.Duration `json:"provisionTime,omitempty"`
}

// VirtualMachineDiskStatus defines the observed state of VirtualMachineDisk.
type VirtualMachineDiskStatus struct {
	// Size is the current size of the disk.
	// +kubebuilder:validation:Optional
	Size resource.Quantity `json:"size,omitempty"`
	// Conditions contain the latest observations of VirtualMachineDisk state.
	Conditions []metav1.Condition `json:"conditions,omitempty"`
	// ProvisionTime provides the gdisk provision time like time to ready, time
	// spent for downloading image etc.
	// +kubebuilder:validation:Optional
	ProvisionTime *VirtualMachineDiskProvisionTime `json:"provisionTime,omitempty"`
	// VirtualMachineAttachments is the list of VirtualMachine instances the
	// VirtualMachineDisk is attached to.
	// +kubebuilder:validation:Optional
	VirtualMachineAttachments []VirtualMachineAttachment `json:"virtualMachineAttachments"`
	// StorageClassName reflects the storage class used by this disk.
	// +kubebuilder:validation:Optional
	StorageClassName string `json:"storageClassName,omitempty"`
	// Phase is the current phase of the data volume
	// +kubebuilder:validation:Optional
	Phase VirtualMachineDiskPhase `json:"phase,omitempty"`
	// Progress is the current progress of the DataVolume
	// transfer operation. Value between 0 and 100 inclusive, N/A if not
	// available
	// +kubebuilder:validation:Optional
	Progress cdiv1.DataVolumeProgress `json:"progress,omitempty"`
	// PersistentVolumeClaimInfo contains the relevant information about the underlying PVC.
	// +kubebuilder:validation:Optional
	PersistentVolumeClaimInfo *PersistentVolumeClaimInfo `json:"persistentVolumeClaimInfo,omitempty"`
}

// VirtualMachineAttachment contains information how this VirtualMachineDisk is
// attached and what it is attached to.
type VirtualMachineAttachment struct {
	// Name is the name of an attached VirtualMachine.
	Name string `json:"name"`
	// UID is the UID of the attached VirtualMachine.
	UID types.UID `json:"uid"`
	// AutoDelete is the "AutoDelete" setting for this attachment.
	AutoDelete bool `json:"autoDelete"`
	// ReadOnly is the "ReadOnly" setting for this attachment.
	// +kubebuilder:validation:Optional
	ReadOnly bool `json:"readOnly,omitempty"`
}

// PersistentVolumeClaimInfo contains the relevant information about the PVC.
type PersistentVolumeClaimInfo struct {
	// Capacity is the capacity on the PVC status.
	// +optional
	Capacity corev1.ResourceList `json:"capacity,omitempty"`
	// Requests is the resources requested by the PVC spec.
	// +optional
	Requests corev1.ResourceList `json:"requests,omitempty"`
	// VolumeMode is the type of the volume, which can be Filesystem or Block.
	// +optional
	VolumeMode *corev1.PersistentVolumeMode `json:"volumeMode,omitempty"`
}

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status
//+kubebuilder:resource:shortName={gdisk}
//+kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"
//+kubebuilder:printcolumn:name="Phase",type="string",JSONPath=".status.phase"
//+kubebuilder:printcolumn:name="Progress",type="string",JSONPath=".status.progress"
//+kubebuilder:printcolumn:name="Size",type="string",JSONPath=".spec.size"

// VirtualMachineDisk is the Schema for the virtualmachinedisks API.
// The spec of a VirtualMachineDisk is immutable.
type VirtualMachineDisk struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   VirtualMachineDiskSpec   `json:"spec,omitempty"`
	Status VirtualMachineDiskStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// VirtualMachineDiskList contains a list of VirtualMachineDisk.
type VirtualMachineDiskList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []VirtualMachineDisk `json:"items"`
}

func init() {
	SchemeBuilder.Register(&VirtualMachineDisk{}, &VirtualMachineDiskList{})
}
