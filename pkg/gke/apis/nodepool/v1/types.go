package v1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// NodePoolSpec defines the desired state of NodePool.
type NodePoolSpec struct {
	// ClusterName points to the cluster that contains this node pool. This field
	// is optional for control plane and load balancer node pools because it must
	// refer the enclosing cluster, in which case this field should either be
	// empty or match the enclosing cluster's name. This field is required for
	// worker node pools.
	// +kubebuilder:validation:Optional
	ClusterName string `json:"clusterName,omitempty"`
	// Nodes contain the list of machine addresses in the node pool.
	// +kubebuilder:validation:MinItems=1
	Nodes []Node `json:"nodes"`
}

// Node specifies the node parameters.
type Node struct {
	// Address specifies the default IPv4 address for SSH access and Kubernetes node.
	// Example: 192.168.0.1
	// +kubebuilder:validation:MinLength=1
	Address string `json:"address"`
	// K8sIP specifies the Kubernetes node IPv4 address. If present, it overrides the
	// default address. Example: 172.16.0.1
	// This value cannot be mutated after creation.
	// +kubebuilder:validation:Optional
	K8sIP *string `json:"k8sIP,omitempty"`
}

// GetK8sIP returns the IP that to be used by k8s.
func (n *Node) GetK8sIP() string {
	if n.K8sIP != nil {
		return *n.K8sIP
	}
	return n.Address
}

// Versions map from version string (could be either GKEVersion or AnthosBareMetalVersion) to count of machines.
type Versions map[string]int

// NodePoolStatus defines the observed state of NodePool.
type NodePoolStatus struct {
	// NodeDraining is a map of nodes currently draining and pods counts yet to drain.
	NodesDraining map[string]int `json:"nodesDraining,omitempty"`
	// NodesDrained is a set of nodes drained.
	NodesDrained []string `json:"nodesDrained,omitempty"`
}

// +genclient
// +genclient:noStatus
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// NodePool is the Schema for the nodepools API.
type NodePool struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata"`

	Spec   NodePoolSpec   `json:"spec"`
	Status NodePoolStatus `json:"status,omitempty"`
}

// +genclient
// +genclient:onlyVerbs=get
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// NodePoolList contains a list of NodePool.
type NodePoolList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []NodePool `json:"items"`
}
