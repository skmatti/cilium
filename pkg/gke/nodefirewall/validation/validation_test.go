//go:build !privileged_tests
// +build !privileged_tests

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

package validation

import (
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	utils "github.com/cilium/cilium/pkg/gke/nodefirewall/test"
	"gke-internal/gke-node-firewall/pkg/apis/nodenetworkpolicy/v1alpha1"
)

func TestValidation(t *testing.T) {
	for _, tc := range []struct {
		desc        string
		policy      *v1alpha1.NodeNetworkPolicy
		expectError bool
	}{
		{
			desc: "Deny all (nil Ingress)",
			policy: &v1alpha1.NodeNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: "deny-all-policy",
				},
				Spec: v1alpha1.NodeNetworkPolicySpec{},
			},
			expectError: false,
		},
		{
			desc: "Allow all (empty Ingress)",
			policy: &v1alpha1.NodeNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: "allow-all-empty-ingress-policy",
				},
				Spec: v1alpha1.NodeNetworkPolicySpec{
					Ingress: []v1alpha1.NodeNetworkPolicyIngressRule{},
				},
			},
			expectError: false,
		},
		{
			desc: "Allow all (nil From and Ports)",
			policy: &v1alpha1.NodeNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: "allow-all-nil-from-and-ports-policy",
				},
				Spec: v1alpha1.NodeNetworkPolicySpec{
					Ingress: []v1alpha1.NodeNetworkPolicyIngressRule{
						{},
					},
				},
			},
			expectError: false,
		},
		{
			desc: "Allow all sources (empty From)",
			policy: &v1alpha1.NodeNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: "allow-all-sources-empty-from-policy",
				},
				Spec: v1alpha1.NodeNetworkPolicySpec{
					Ingress: []v1alpha1.NodeNetworkPolicyIngressRule{
						{
							From: []v1alpha1.NodeNetworkPolicyPeer{},
							Ports: []v1alpha1.NodeNetworkPolicyPort{
								{
									Protocol: utils.ProtocolToPtr(v1alpha1.ProtocolTCP),
									Port:     utils.Int32ToPtr(8080),
								},
							},
						},
					},
				},
			},
			expectError: false,
		},
		{
			desc: "Allow all ports (nil Ports)",
			policy: &v1alpha1.NodeNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: "allow-all-ports-policy",
				},
				Spec: v1alpha1.NodeNetworkPolicySpec{
					Ingress: []v1alpha1.NodeNetworkPolicyIngressRule{
						{
							From: []v1alpha1.NodeNetworkPolicyPeer{
								{IPBlock: &v1alpha1.IPBlock{CIDR: "10.0.0.0/28"}},
							},
						},
					},
				},
			},
			expectError: false,
		},
		{
			desc: "Allow all tcp (empty Port)",
			policy: &v1alpha1.NodeNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: "allow-all-tcp-empty-port-policy",
				},
				Spec: v1alpha1.NodeNetworkPolicySpec{
					Ingress: []v1alpha1.NodeNetworkPolicyIngressRule{
						{
							From: []v1alpha1.NodeNetworkPolicyPeer{
								{IPBlock: &v1alpha1.IPBlock{CIDR: "10.0.0.0/28"}},
							},
							Ports: []v1alpha1.NodeNetworkPolicyPort{{}},
						},
					},
				},
			},
			expectError: false,
		},
		{
			desc: "Invalid source",
			policy: &v1alpha1.NodeNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: "invalid-source-policy",
				},
				Spec: v1alpha1.NodeNetworkPolicySpec{
					Ingress: []v1alpha1.NodeNetworkPolicyIngressRule{
						{
							From: []v1alpha1.NodeNetworkPolicyPeer{
								{IPBlock: &v1alpha1.IPBlock{CIDR: "10.0.256.0/28"}},
							},
						},
					},
				},
			},
			expectError: true,
		},
		{
			desc: "Invalid CIDR in Expect block",
			policy: &v1alpha1.NodeNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: "invalid-CIDR-in-Except-policy",
				},
				Spec: v1alpha1.NodeNetworkPolicySpec{
					Ingress: []v1alpha1.NodeNetworkPolicyIngressRule{
						{
							From: []v1alpha1.NodeNetworkPolicyPeer{
								{IPBlock: &v1alpha1.IPBlock{
									CIDR:   "10.0.0.0/28",
									Except: []string{"10.0.4.1", "10.256.0.1"},
								}},
							},
						},
					},
				},
			},
			expectError: true,
		},
		{
			desc: "Invalid protocol",
			policy: &v1alpha1.NodeNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: "invalid-protocol-policy",
				},
				Spec: v1alpha1.NodeNetworkPolicySpec{
					Ingress: []v1alpha1.NodeNetworkPolicyIngressRule{
						{
							Ports: []v1alpha1.NodeNetworkPolicyPort{
								{
									Protocol: utils.ProtocolToPtr("invalid-protocol"),
								},
							},
						},
					},
				},
			},
			expectError: true,
		},
		{
			desc: "Invalid port",
			policy: &v1alpha1.NodeNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: "invalid-port-policy",
				},
				Spec: v1alpha1.NodeNetworkPolicySpec{
					Ingress: []v1alpha1.NodeNetworkPolicyIngressRule{
						{
							Ports: []v1alpha1.NodeNetworkPolicyPort{
								{
									Port: utils.Int32ToPtr(68756),
								},
							},
						},
					},
				},
			},
			expectError: true,
		},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			err := Validate(tc.policy)
			if err != nil && !tc.expectError {
				t.Fatalf("Expected no error but got %v", err)
			}
			if err == nil && tc.expectError {
				t.Fatalf("Expected non-nil error but got no error")
			}
		})
	}
}
