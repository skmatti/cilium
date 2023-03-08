package multinic

const (
	// NICInfoAnnotationKey specifies the mapping between the first IP
	// addresses and the PCI BDF number on the node.
	NICInfoAnnotationKey = "networking.gke.io/nic-info"
)

type NICInfoRefs []NICInfoRef

// NICInfoRef specifies the mapping between a NIC's first v4 IP and its
// PCI address on the node.
type NICInfoRef struct {
	// First v4 IP address of the interface.
	BirthIP string `json:"birthIP,omitempty"`
	// PCI address of this device on the node.
	PCIAddress string `json:"pciAddress,omitempty"`
	// Name is the birth name of this interface at node boot time.
	BirthName string `json:"birthName,omitempty"`
}
