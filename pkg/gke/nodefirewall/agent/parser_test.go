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
	"reflect"
	"testing"

	"github.com/cilium/cilium/pkg/gke/nodefirewall/test"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/google/go-cmp/cmp"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"

	"gke-internal/gke-node-firewall/pkg/apis/nodenetworkpolicy/v1alpha1"
)

func TestSanitizePolicy(t *testing.T) {
	for _, tc := range []struct {
		desc         string
		policyObj    interface{}
		expectPolicy *v1alpha1.NodeNetworkPolicy
		expectErr    bool
	}{
		{
			desc:         "nil object",
			policyObj:    nil,
			expectPolicy: nil,
			expectErr:    true,
		},
		{
			desc:         "node network policy",
			policyObj:    &v1alpha1.NodeNetworkPolicy{},
			expectPolicy: &v1alpha1.NodeNetworkPolicy{},
			expectErr:    false,
		},
		{
			desc: "unrecoverable delete state",
			policyObj: &cache.DeletedFinalStateUnknown{
				Obj: &networkingv1.NetworkPolicy{},
			},
			expectPolicy: nil,
			expectErr:    true,
		},
		{
			desc: "recoverable delete state",
			policyObj: &cache.DeletedFinalStateUnknown{
				Obj: &v1alpha1.NodeNetworkPolicy{
					TypeMeta: metav1.TypeMeta{
						Kind:       "NodeNetworkPolicy",
						APIVersion: "v1alpha1",
					},
				},
			},
			expectPolicy: &v1alpha1.NodeNetworkPolicy{
				TypeMeta: metav1.TypeMeta{
					Kind:       "NodeNetworkPolicy",
					APIVersion: "v1alpha1",
				},
			},
			expectErr: false,
		},
		{
			desc:         "not a node network policy",
			policyObj:    &metav1.ObjectMeta{},
			expectPolicy: nil,
			expectErr:    true,
		},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			gotPolicy, ok := objToNodeNetworkPolicy(tc.policyObj)
			if ok && tc.expectErr {
				t.Fatal("Expected error but got no error")
			}
			if !ok && !tc.expectErr {
				t.Fatal("Expected no error but got error")
			}
			if diff := cmp.Diff(tc.expectPolicy, gotPolicy); diff != "" {
				t.Fatalf("Got diff for Node Network Policy (-want +got):\n%s", diff)
			}
		})
	}
}

func TestNNPToCiliumPolicyRules(t *testing.T) {
	for _, tc := range []struct {
		desc   string
		policy *v1alpha1.NodeNetworkPolicy
		expect api.Rule
	}{
		{
			desc:   "empty policy",
			policy: &v1alpha1.NodeNetworkPolicy{},
			expect: api.Rule{
				NodeSelector: api.EndpointSelector{
					LabelSelector: &slim_metav1.LabelSelector{},
				},
				Ingress: []api.IngressRule{},
			},
		},
		{
			desc: "policy with From CIDR",
			policy: test.NewNodeNetworkPolicy("from-cidr-policy", func(nnp *v1alpha1.NodeNetworkPolicy) {
				nnp.Spec.Ingress = []v1alpha1.NodeNetworkPolicyIngressRule{
					{
						From: []v1alpha1.NodeNetworkPolicyPeer{
							{
								IPBlock: &v1alpha1.IPBlock{
									CIDR: "10.5.6.4/24",
								},
							},
						},
					},
				}
			}),
			expect: api.Rule{
				NodeSelector: api.EndpointSelector{
					LabelSelector: &slim_metav1.LabelSelector{},
				},
				Ingress: []api.IngressRule{
					{
						FromCIDRSet: api.CIDRRuleSlice{
							{Cidr: "10.5.6.4/24"},
						},
					},
				},
			},
		},
		{
			desc: "policy with From CIDR and Except CIDRs",
			policy: test.NewNodeNetworkPolicy("from-cidr-with-except-policy", func(nnp *v1alpha1.NodeNetworkPolicy) {
				nnp.Spec.Ingress = []v1alpha1.NodeNetworkPolicyIngressRule{
					{
						From: []v1alpha1.NodeNetworkPolicyPeer{
							{
								IPBlock: &v1alpha1.IPBlock{
									CIDR: "10.5.6.4/24",
									Except: []string{
										"10.5.6.230/32",
									},
								},
							},
						},
					},
				}
			}),
			expect: api.Rule{
				NodeSelector: api.EndpointSelector{
					LabelSelector: &slim_metav1.LabelSelector{},
				},
				Ingress: []api.IngressRule{
					{
						FromCIDRSet: api.CIDRRuleSlice{
							{
								Cidr: "10.5.6.4/24",
								ExceptCIDRs: []api.CIDR{
									"10.5.6.230/32",
								},
							},
						},
					},
				},
			},
		},
		{
			desc: "policy with name base-allow-node",
			policy: test.NewNodeNetworkPolicy(baseNodeToNodePolicyName, func(nnp *v1alpha1.NodeNetworkPolicy) {
				nnp.Spec.Ingress = []v1alpha1.NodeNetworkPolicyIngressRule{
					{
						From: []v1alpha1.NodeNetworkPolicyPeer{
							{
								IPBlock: &v1alpha1.IPBlock{
									CIDR: "1.1.1.20/24",
								},
							},
							{
								IPBlock: &v1alpha1.IPBlock{
									CIDR: "1.1.2.20/24",
								},
							},
						},
					},
				}
			}),
			expect: api.Rule{
				NodeSelector: api.EndpointSelector{
					LabelSelector: &slim_metav1.LabelSelector{},
				},
				Ingress: []api.IngressRule{
					{
						FromEntities: api.EntitySlice{api.EntityCluster},
					},
				},
			},
		},
		{
			desc: "policy with multiple From CIDRs",
			policy: test.NewNodeNetworkPolicy("from-cidr-contains-host-policy", func(nnp *v1alpha1.NodeNetworkPolicy) {
				nnp.Spec.Ingress = []v1alpha1.NodeNetworkPolicyIngressRule{
					{
						From: []v1alpha1.NodeNetworkPolicyPeer{
							{
								IPBlock: &v1alpha1.IPBlock{
									CIDR: "10.5.6.4/24",
								},
							},
							{
								IPBlock: &v1alpha1.IPBlock{
									CIDR: "1.1.2.20/24",
								},
							},
						},
					},
				}
			}),
			expect: api.Rule{
				NodeSelector: api.EndpointSelector{
					LabelSelector: &slim_metav1.LabelSelector{},
				},
				Ingress: []api.IngressRule{
					{
						FromCIDRSet: api.CIDRRuleSlice{
							{
								Cidr: "10.5.6.4/24",
							},
						},
					},
					{
						FromCIDRSet: api.CIDRRuleSlice{
							{
								Cidr: "1.1.2.20/24",
							},
						},
					},
				},
			},
		},
		{
			desc: "policy with non-empty label selector",
			policy: test.NewNodeNetworkPolicy("from-cidr-with-except-policy", func(nnp *v1alpha1.NodeNetworkPolicy) {
				nnp.Spec.NodeSelector = metav1.LabelSelector{
					MatchLabels: map[string]string{
						"cloud.google.com/gke-nodepool": "default-pool",
					},
				}
				nnp.Spec.Ingress = []v1alpha1.NodeNetworkPolicyIngressRule{
					{
						From: []v1alpha1.NodeNetworkPolicyPeer{
							{
								IPBlock: &v1alpha1.IPBlock{
									CIDR: "10.5.6.4/24",
									Except: []string{
										"10.5.6.230/32",
									},
								},
							},
						},
					},
				}
			}),
			expect: api.Rule{
				NodeSelector: api.EndpointSelector{
					LabelSelector: &slim_metav1.LabelSelector{
						MatchLabels: map[string]string{
							"cloud.google.com/gke-nodepool": "default-pool",
						},
					},
				},
				Ingress: []api.IngressRule{
					{
						FromCIDRSet: api.CIDRRuleSlice{
							{
								Cidr: "10.5.6.4/24",
								ExceptCIDRs: []api.CIDR{
									"10.5.6.230/32",
								},
							},
						},
					},
				},
			},
		},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			tc.expect.Labels = getPolicyLabels(tc.policy.Name)
			tc.expect.NodeSelector = api.NewESFromK8sLabelSelector("", tc.expect.NodeSelector.LabelSelector)
			for i := range tc.expect.Ingress {
				tc.expect.Ingress[i].SetAggregatedSelectors()
			}
			gotRules, err := nnpToCiliumPolicyRules(tc.policy)
			if err != nil {
				t.Fatalf("nnpToCiliumPolicyRules(%s) = %v, want nil", tc.policy.Name, err)
			}
			if len(gotRules) != 1 {
				t.Fatalf("Expected number of rules to be 1, got %d", len(gotRules))
			}
			if gotRules[0] == nil {
				t.Fatalf("Expected non-nil policy rule in policy rules %v", gotRules)
			}

			gotRule := *gotRules[0]
			comparer := cmp.Comparer(func(a, b api.Rule) bool {
				return reflect.DeepEqual(a, b)
			})
			if diff := cmp.Diff(tc.expect, gotRule, comparer); diff != "" {
				t.Fatalf("Got diff for policy.Rules (-want +got):\n%s", diff)
			}
		})
	}
}
