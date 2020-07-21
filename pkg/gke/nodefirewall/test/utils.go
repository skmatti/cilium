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

package test

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"gke-internal/gke-node-firewall/pkg/apis/nodenetworkpolicy/v1alpha1"
)

// NewNodeNetworkPolicy returns a node network policy for given namespaced name
// and a function that operates on the newly created policy.
func NewNodeNetworkPolicy(name string, fn func(*v1alpha1.NodeNetworkPolicy)) *v1alpha1.NodeNetworkPolicy {
	policy := &v1alpha1.NodeNetworkPolicy{
		TypeMeta: metav1.TypeMeta{
			Kind:       "NodeNetworkPolicy",
			APIVersion: "networking/v1alpha1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		Spec: v1alpha1.NodeNetworkPolicySpec{
			NodeSelector: metav1.LabelSelector{},
			Ingress:      []v1alpha1.NodeNetworkPolicyIngressRule{},
		},
	}
	fn(policy)
	return policy
}

// ProtocolToPtr returns a pointer to given protocol.
func ProtocolToPtr(protocol v1alpha1.Protocol) *v1alpha1.Protocol {
	return &protocol
}

// Int32ToPtr returns a pointer to given int32.
func Int32ToPtr(protocol int32) *int32 {
	return &protocol
}
