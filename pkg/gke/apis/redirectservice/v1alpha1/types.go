/*
Copyright 2020 Google LLC

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

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// RedirectService describes the specification used by google redirect
// service. There can be at most one copy of this resource in the cluster.
// This will be enforced using validation proposed in
// https://github.com/kubernetes-sigs/kubebuilder/issues/1074
// If the resource does not exist, no explicit redition will be applied..
type RedirectService struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// Spec is the desired configuration for redirect service.
	Spec RedirectServiceSpec `json:"spec,omitempty"`
}

// RedirectServiceSpec provides the specification for the redirectservice resource.
// It is applicable to a specific namespace.
type RedirectServiceSpec struct {
	// Redirect specifies the options for traffic redirection.
	Redirect RedirectSpec `json:"redirect"`
}

// +k8s:openapi-gen=true
type RedirectServiceType string

const (
	NodeLocalDNSRedirectServiceType = RedirectServiceType("nodelocaldns")
)

// +k8s:openapi-gen=true
type ServiceProviderType string

const (
	KubeDNSServiceProviderType = ServiceProviderType("kube-dns")
)

// RedirectSpec contains the spec for this redirection service.
// All fields are mandatory.
type RedirectSpec struct {
	// Type specifies the type of service that needs redirection.
	Type RedirectServiceType `json:"type"`
	// Provider specifies the provider of the original service..
	Provider ServiceProviderType `json:"provider"`
}

// +genclient
// +genclient:onlyVerbs=get
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// RedirectServiceList contains a list of RedirectService resources.
type RedirectServiceList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`

	// Items is a slice of RedirectService resources.
	Items []RedirectService `json:"items"`
}
