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

// +genclient
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// NetworkInterface defines the network interface for a pod to connect to a network.
type NetworkInterface struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   NetworkInterfaceSpec   `json:"spec,omitempty"`
	Status NetworkInterfaceStatus `json:"status,omitempty"`
}

// NetworkInterfaceSpec is the specification for the NetworkInterface resource.
type NetworkInterfaceSpec struct {
	// NetworkName refers to a network object that this NetworkInterface is connected.
	// +required
	NetworkName string `json:"networkName"`

	// IpAddresses specifies the static IP addresses on this NetworkInterface.
	// Each IPAddress may contain subnet mask. If subnet mask is not included, /32 is taken as default.
	// For example, IPAddress input 1.2.3.4 will be taken as 1.2.3.4/32. Alternatively, the input can be 1.2.3.4/24
	// with subnet mask of /24.
	// +optional
	IpAddresses []string `json:"ipAddresses,omitempty"`

	// Macddress specifies the static MAC address on this NetworkInterface.
	// +optional
	MacAddress *string `json:"macAddress,omitempty"`
}

// NetworkInterfaceStatus is the status for the NetworkInterface resource.
type NetworkInterfaceStatus struct {
	// IpAddresses are the IP addresses assigned to the NetworkInterface.
	IpAddresses []string `json:"ipAddresses,omitempty"`
	// MacAddress is the MAC address assigned to the NetworkInterface.
	MacAddress string `json:"macAddress,omitempty"`

	//// Conditions include the the conditions associated with this Interface
	// Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +genclient
// +genclient:onlyVerbs=get
// +kubebuilder:object:root=true
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// NetworkInterfaceList contains a list of NetworkInterface resources.
type NetworkInterfaceList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`

	// Items is a slice of NetworkInterface resources.
	Items []NetworkInterface `json:"items"`
}
