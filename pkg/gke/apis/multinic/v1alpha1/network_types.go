/*
Copyright 2021 Google LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1alpha1

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

// NetworkType is the type of network.
type NetworkType string

const (
	L2NetworkType      = NetworkType("L2")
	L3NetworkType      = NetworkType("L3")
	DefaultNetworkName = "pod-network"
)

// +genclient
// +genclient:nonNamespaced
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// Network represent a logical network on the K8s Cluster.
// This logical network depends on the host networking setup on cluster nodes.
type Network struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   NetworkSpec   `json:"spec,omitempty"`
	Status NetworkStatus `json:"status,omitempty"`
}

// NetworkSpec contains the specifications for network object
type NetworkSpec struct {
	// Type defines type of network.
	// Valid options includes: L2, L3
	// L2 network type enables L2 connectivity on the network.
	// L3 network type enables L3 connectivity on the network.
	// +required
	Type NetworkType `json:"type"`

	//// Ipam defines IPAM configurations
	//// +optional
	//Ipam IpamConfig `json:"ipam,omitempty"`

	// NodeInterfaceMatcher defines the matcher to discover the corresponding node interface associated with the network.
	// If unspecified, default to the host network interface with Node IP.
	// +optional
	NodeInterfaceMatcher NodeInterfaceMatcher `json:"nodeInterfaceMatcher,omitempty"`

	//// L2NetworkConfig includes all the network config related to L2 type network
	//// +optional
	//L2NetworkConfig *L2NetworkConfig `json:"l2network,omitempty"`
}

// NetworkStatus containers the status information related to the network.
type NetworkStatus struct{}

//// IpamConfig contains
//// For one network, only one IPAM config is
//type IpamConfig struct {
//	// Dhcp contains the Dhcp configurations.
//	// If unspecified, DHCP is considered disabled.
//	// +optional
//	Dhcp *DhcpConfig `json:"dhcp,omitempty"`
//
//	// Post MVP
//	//Range *RangeConfig
//}

//// DhcpConfig contains DHCP configurations.
//type DhcpConfig struct{}

// NodeInterfaceMatcher defines criteria to find the matching interface on host networking.
type NodeInterfaceMatcher struct {
	// InterfaceName specifies the interface name to search on the node.
	// +optional
	InterfaceName *string `json:"interfaceName,omitempty"`

	////InterfaceCIDR specified the interface CIDR. The first interface with matching CIDR will be used as north
	////interface.
	//InterfaceCIDR *string `json:"interfaceCIDR,omitempty"`
}

//// L2NetworkConfig contains configurations for L2 type network.
//type L2NetworkConfig struct {
//	// VlanId is the vlan ID used for the network.
//	// If unspecified, vlan tagging is not enabled.
//	// +optional
//	VlanId *int `json:"vlanId,omitempty"`
//}

// +genclient
// +genclient:nonNamespaced
// +genclient:onlyVerbs=get
// +kubebuilder:object:root=true
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// NetworkList contains a list of Network resources.
type NetworkList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`

	// Items is a slice of Network resources.
	Items []Network `json:"items"`
}
