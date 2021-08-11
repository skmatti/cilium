/*
Copyright 2021 The Kubernetes Authors.

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

package annotation

import "encoding/json"

const (
	InterfaceAnnotationKey = "anthos.io/interfaces"
)

// InterfaceAnnotation is the value of the interface annotation.
type InterfaceAnnotation []InterfaceRef

// InterfaceRef specifies the reference to network interface.
// All fields are mutual exclusive.
// Either Network or Interface field can to be specified.
type InterfaceRef struct {
	// InterfaceName is the name of the interface in pod network namespace.
	InterfaceName string `json:"interfaceName,omitempty"`
	// Network refers to a network object within the cluster.
	// When network is specified, NetworkInterface object is optionally generated with default configuration.
	Network *string `json:"network,omitempty"`
	// Interface reference the NetworkInterface object within the namespace.
	Interface *string `json:"interface,omitempty"`
}

// ParseAnnotation parse the given annotation.
func ParseAnnotation(annotation string) (InterfaceAnnotation, error) {
	ret := &InterfaceAnnotation{}
	err := json.Unmarshal([]byte(annotation), ret)
	return *ret, err
}
