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

package agent

import (
	"context"
	"testing"
	"time"

	testutils "github.com/cilium/cilium/pkg/gke/nodefirewall/test"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/policy/api"
	"gke-internal/gke-node-firewall/pkg/apis/nodenetworkpolicy/v1alpha1"
	nodefirewallclient "gke-internal/gke-node-firewall/pkg/client/nodenetworkpolicy/clientset/versioned/fake"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

var (
	policies = []*v1alpha1.NodeNetworkPolicy{
		// Non-controller owned policy.
		testutils.NewNodeNetworkPolicy(
			"non-controller-owned-policy",
			func(networkPolicy *v1alpha1.NodeNetworkPolicy) {
				networkPolicy.Spec.NodeSelector = metav1.LabelSelector{
					MatchLabels: map[string]string{
						"cloud.google.com/gke-nodepool": "other-pool",
					},
				}
			},
		),
		// Deleted Policy.
		testutils.NewNodeNetworkPolicy(
			"deleted-policy",
			func(networkPolicy *v1alpha1.NodeNetworkPolicy) {
				ts := metav1.NewTime(time.Now())
				networkPolicy.SetDeletionTimestamp(&ts)
				networkPolicy.Spec.NodeSelector = metav1.LabelSelector{
					MatchLabels: map[string]string{
						"cloud.google.com/gke-nodepool": "default-pool",
					},
				}
			},
		),
		// Controller-owned policy.
		testutils.NewNodeNetworkPolicy(
			"controller-owned-policy",
			func(networkPolicy *v1alpha1.NodeNetworkPolicy) {
				networkPolicy.Spec.NodeSelector = metav1.LabelSelector{
					MatchLabels: map[string]string{
						"cloud.google.com/gke-nodepool": "default-pool",
					},
				}
			},
		),
		// Both from and ports are nil.
		testutils.NewNodeNetworkPolicy(
			"empty-ingress-policy",
			func(networkPolicy *v1alpha1.NodeNetworkPolicy) {
				networkPolicy.Spec.NodeSelector = metav1.LabelSelector{
					MatchLabels: map[string]string{
						"cloud.google.com/gke-nodepool": "default-pool",
					},
				}
				networkPolicy.Spec.Ingress = []v1alpha1.NodeNetworkPolicyIngressRule{
					{
						From:  nil,
						Ports: nil,
					},
				}
			},
		),
		// Nil Ingress.
		testutils.NewNodeNetworkPolicy(
			"nil-ingress-policy",
			func(networkPolicy *v1alpha1.NodeNetworkPolicy) {
				networkPolicy.Spec.NodeSelector = metav1.LabelSelector{
					MatchLabels: map[string]string{
						"cloud.google.com/gke-nodepool": "default-pool",
					},
				}
			},
		),
	}

	invalidPolicies = []*v1alpha1.NodeNetworkPolicy{
		// Invalid Protocol.
		testutils.NewNodeNetworkPolicy(
			"invalid-protocol-policy",
			func(networkPolicy *v1alpha1.NodeNetworkPolicy) {
				networkPolicy.Spec.NodeSelector = metav1.LabelSelector{
					MatchLabels: map[string]string{
						"cloud.google.com/gke-nodepool": "default-pool",
					},
				}
				networkPolicy.Spec.Ingress = []v1alpha1.NodeNetworkPolicyIngressRule{
					{
						Ports: []v1alpha1.NodeNetworkPolicyPort{
							{
								Protocol: testutils.ProtocolToPtr("INVALID"),
							},
						},
					},
				}
			},
		),
		// Nil/Empty CIDR block.
		testutils.NewNodeNetworkPolicy(
			"nil-CIDR-policy",
			func(networkPolicy *v1alpha1.NodeNetworkPolicy) {
				networkPolicy.Spec.NodeSelector = metav1.LabelSelector{
					MatchLabels: map[string]string{
						"cloud.google.com/gke-nodepool": "default-pool",
					},
				}
				networkPolicy.Spec.Ingress = []v1alpha1.NodeNetworkPolicyIngressRule{
					{
						From: []v1alpha1.NodeNetworkPolicyPeer{
							{
								IPBlock: &v1alpha1.IPBlock{
									CIDR: "",
								},
							},
						},
					},
				}
			},
		),
		// Invalid CIDR block.
		testutils.NewNodeNetworkPolicy(
			"invalid-CIDR-policy",
			func(networkPolicy *v1alpha1.NodeNetworkPolicy) {
				networkPolicy.Spec.NodeSelector = metav1.LabelSelector{
					MatchLabels: map[string]string{
						"cloud.google.com/gke-nodepool": "default-pool",
					},
				}
				networkPolicy.Spec.Ingress = []v1alpha1.NodeNetworkPolicyIngressRule{
					{
						From: []v1alpha1.NodeNetworkPolicyPeer{
							{
								IPBlock: &v1alpha1.IPBlock{
									CIDR: "10.5.6.4",
								},
							},
						},
					},
				}
			},
		),
		// Invalid Except CIDR blocks.
		testutils.NewNodeNetworkPolicy(
			"invalid-except-CIDRs-policy",
			func(networkPolicy *v1alpha1.NodeNetworkPolicy) {
				networkPolicy.Spec.NodeSelector = metav1.LabelSelector{
					MatchLabels: map[string]string{
						"cloud.google.com/gke-nodepool": "default-pool",
					},
				}
				networkPolicy.Spec.Ingress = []v1alpha1.NodeNetworkPolicyIngressRule{
					{
						From: []v1alpha1.NodeNetworkPolicyPeer{
							{
								IPBlock: &v1alpha1.IPBlock{
									CIDR: "10.5.6.4/24",
									Except: []string{
										"", "10.34.3.0", "10.5.6.230",
									},
								},
							},
						},
					},
				}
			},
		),
	}
	nodeFirewallClient = nodefirewallclient.NewSimpleClientset()
)

func newNodeFirewallAgent() *NodeFirewallAgent {
	nfAgent := NewNodeFirewallAgent(fake.NewSimpleClientset(), nodeFirewallClient, &fakePolicyManager{})
	nfAgent.hasSynced = func() bool {
		return true
	}
	return nfAgent
}

func addPolicy(nfAgent *NodeFirewallAgent, policy *v1alpha1.NodeNetworkPolicy) {
	nodeFirewallClient.NetworkingV1alpha1().NodeNetworkPolicies().Create(context.TODO(), policy, metav1.CreateOptions{})
	nfAgent.policyInformer.GetIndexer().Add(policy)
}

func TestSync(t *testing.T) {
	for _, tc := range []struct {
		desc        string
		policy      *v1alpha1.NodeNetworkPolicy
		expectError bool
	}{
		{
			desc:        "non-controller owned policy",
			policy:      policies[0],
			expectError: false,
		},
		{
			desc:        "deleted policy",
			policy:      policies[1],
			expectError: false,
		},
		{
			desc:        "controller owned policy",
			policy:      policies[2],
			expectError: false,
		},
		{
			desc:        "both from and ports are nil",
			policy:      policies[3],
			expectError: false,
		},
		{
			desc:        "nil ingress",
			policy:      policies[4],
			expectError: false,
		},
		{
			desc:        "invalid protocol",
			policy:      invalidPolicies[0],
			expectError: true,
		},
		{
			desc:        "empty CIDR block",
			policy:      invalidPolicies[1],
			expectError: true,
		},
		{
			desc:        "invalid CIDR block",
			policy:      invalidPolicies[2],
			expectError: true,
		},
		{
			desc:        "invalid except CIDR blocks",
			policy:      invalidPolicies[3],
			expectError: true,
		},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			nfAgent := newNodeFirewallAgent()
			addPolicy(nfAgent, tc.policy)

			err := nfAgent.sync(tc.policy.Name)

			if err != nil && !tc.expectError {
				t.Fatalf("Expected no error, but got err: %v", err)
			}

			if err == nil && tc.expectError {
				t.Fatalf("Expected error but got no error")
			}
		})
	}
}

type fakePolicyManager struct {
	OnPolicyAdd    func(rules api.Rules, opts *policy.AddOptions) (newRev uint64, err error)
	OnPolicyDelete func(labels labels.LabelArray) (newRev uint64, err error)
}

func (f *fakePolicyManager) PolicyAdd(rules api.Rules, opts *policy.AddOptions) (newRev uint64, err error) {
	return 0, nil
}

func (f *fakePolicyManager) PolicyDelete(labels labels.LabelArray) (newRev uint64, err error) {
	return 0, nil
}
