// Copyright 2022 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build !privileged_tests
// +build !privileged_tests

package controller

import (
	"testing"

	ciliumModels "github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/fqdn/re"
	"github.com/cilium/cilium/pkg/gke/apis/fqdnnetworkpolicy/v1alpha1"
	ciliumK8s "github.com/cilium/cilium/pkg/k8s"
	ciliumConst "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	ciliumLbls "github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/policy/api"
	testidentity "github.com/cilium/cilium/pkg/testutils/identity"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sTypes "k8s.io/apimachinery/pkg/types"
)

func testNewPolicyRepository() *policy.Repository {
	idAllocator := testidentity.NewMockIdentityAllocator(nil)
	repo := policy.NewPolicyRepository(idAllocator, nil, nil)
	repo.GetSelectorCache().SetLocalIdentityNotifier(testidentity.NewDummyIdentityNotifier())
	return repo
}

func TestDNSProxyRedirect(t *testing.T) {
	re.InitRegexCompileLRU(defaults.FQDNRegexCompileLRUSize)
	// This policy only allows egress traffic to kube-dns
	emptyFQDNPolicy := &v1alpha1.FQDNNetworkPolicy{Spec: v1alpha1.FQDNNetworkPolicySpec{}}
	rule, err := parseFQDNNetworkPolicy(emptyFQDNPolicy)
	if err != nil {
		t.Fatalf("Error parsing FQDN network policy: %v", err)
	}
	repo := testNewPolicyRepository()
	repo.AddList(api.Rules{rule})

	// Note: The policy.SearchContext construct is also used by
	// pkg/k8s/network_policy_test.go to validate Kubernetes Network Policy
	// parsing.
	ctx := policy.SearchContext{
		From: ciliumLbls.LabelArray{
			ciliumLbls.NewLabel(ciliumConst.PodNamespaceLabel, "default", ciliumLbls.LabelSourceK8s),
			ciliumLbls.NewLabel("app", "client", ciliumLbls.LabelSourceK8s),
		},
		To: ciliumLbls.LabelArray{
			ciliumLbls.NewLabel(ciliumConst.PodNamespaceLabel, "kube-system", ciliumLbls.LabelSourceK8s),
			ciliumLbls.NewLabel("k8s-app", "kube-dns", ciliumLbls.LabelSourceK8s),
		},
		Trace: policy.TRACE_VERBOSE,
	}
	// Without specifying a port, traffic to kube-dns is denied.
	if verdict := repo.AllowsEgressRLocked(&ctx); verdict != api.Denied {
		t.Fatalf("AllowsEgressRLocked(ctx=%+v)=%v, want %v", ctx, verdict, api.Denied)
	}

	ctx.DPorts = []*ciliumModels.Port{{Port: 53, Protocol: ciliumModels.PortProtocolUDP}}
	// Port 53, UDP traffic is allowed
	if verdict := repo.AllowsEgressRLocked(&ctx); verdict != api.Allowed {
		t.Fatalf("AllowsEgressRLocked(ctx=%+v)=%v, want %v", ctx, verdict, api.Allowed)
	}

	ctx.DPorts = []*ciliumModels.Port{{Port: 53, Protocol: ciliumModels.PortProtocolTCP}}
	// Port 53, TCP traffic is allowed
	if verdict := repo.AllowsEgressRLocked(&ctx); verdict != api.Allowed {
		t.Fatalf("AllowsEgressRLocked(ctx=%+v)=%v, want %v", ctx, verdict, api.Allowed)
	}

	ctx.To = ciliumLbls.LabelArray{
		ciliumLbls.NewLabel(ciliumConst.PodNamespaceLabel, "default", ciliumLbls.LabelSourceK8s),
		ciliumLbls.NewLabel("app", "be", ciliumLbls.LabelSourceK8s),
	}
	// Port 53, TCP traffic to an endpoint that is not kube-dns is denied.
	if verdict := repo.AllowsEgressRLocked(&ctx); verdict != api.Denied {
		t.Fatalf("AllowsEgressRLocked(ctx=%+v)=%v, want %v", ctx, verdict, api.Denied)
	}
}

func TestPolicyLabels(t *testing.T) {
	for _, tc := range []struct {
		name                             string
		fqdn                             *v1alpha1.FQDNNetworkPolicy
		wantNamespace, wantName, wantUID string
	}{
		{
			name: "no namespace",
			fqdn: &v1alpha1.FQDNNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: "fqdn-policy",
					UID:  k8sTypes.UID("cafe-1a77e"),
				},
			},
			wantNamespace: "default",
			wantName:      "fqdn-policy",
			wantUID:       "cafe-1a77e",
		},
		{
			name: "with namespace",
			fqdn: &v1alpha1.FQDNNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "fqdn-policy",
					Namespace: "app-fe",
					UID:       k8sTypes.UID("cafe-1a77e"),
				},
			},
			wantNamespace: "app-fe",
			wantName:      "fqdn-policy",
			wantUID:       "cafe-1a77e",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			want := []ciliumLbls.Label{
				{
					Key:    ciliumConst.PolicyLabelDerivedFrom,
					Value:  resourceTypeFQDNNetworkPolicy,
					Source: ciliumLbls.LabelSourceK8s,
				},
				{
					Key:    ciliumConst.PolicyLabelNamespace,
					Value:  tc.wantNamespace,
					Source: ciliumLbls.LabelSourceK8s,
				},
				{
					Key:    ciliumConst.PolicyLabelName,
					Value:  tc.wantName,
					Source: ciliumLbls.LabelSourceK8s,
				},
				{
					Key:    ciliumConst.PolicyLabelUID,
					Value:  tc.wantUID,
					Source: ciliumLbls.LabelSourceK8s,
				},
			}
			got := policyLabels(tc.fqdn)
			if diff := cmp.Diff(want, got, cmpopts.SortSlices(labelLess)); diff != "" {
				t.Fatalf("PolicyLabels() had a diff (-want +got):\n%s", diff)
			}
		})
	}
}

func TestPodSelector(t *testing.T) {
	fqdnPolicy := func(ns, name string, sel metav1.LabelSelector) *v1alpha1.FQDNNetworkPolicy {
		return &v1alpha1.FQDNNetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: ns,
				Name:      name,
			},
			Spec: v1alpha1.FQDNNetworkPolicySpec{
				PodSelector: sel,
			},
		}
	}

	for _, tc := range []struct {
		name    string
		in      *v1alpha1.FQDNNetworkPolicy
		pod     slim_metav1.ObjectMeta
		matches bool
	}{
		{
			name: "empty selector",
			in:   fqdnPolicy("default", "fqdn-policy", metav1.LabelSelector{}),
			pod: slim_metav1.ObjectMeta{
				Namespace: "default",
				Name:      "pod1",
				Labels:    map[string]string{"app": "fe"},
			},
			matches: true,
		},
		{
			name: "does not select outside namespace",
			in:   fqdnPolicy("default", "fqdn-policy", metav1.LabelSelector{}),
			pod: slim_metav1.ObjectMeta{
				Namespace: "namespace1",
				Name:      "pod1",
				Labels:    map[string]string{"app": "fe"},
			},
			matches: false,
		},
		{
			name: "match labels exactly works",
			in: fqdnPolicy("default", "fqdn-policy", metav1.LabelSelector{
				MatchLabels: map[string]string{"app": "fe"},
			}),
			pod: slim_metav1.ObjectMeta{
				Namespace: "default",
				Name:      "pod1",
				Labels:    map[string]string{"app": "fe", "name": "ds1"},
			},
			matches: true,
		},
		{
			name: "match expression",
			in: fqdnPolicy("default", "fqdn-policy", metav1.LabelSelector{
				MatchExpressions: []metav1.LabelSelectorRequirement{
					{Key: "name", Operator: metav1.LabelSelectorOpExists},
				},
			}),
			pod: slim_metav1.ObjectMeta{
				Namespace: "default",
				Name:      "pod1",
				Labels:    map[string]string{"app": "fe", "name": "ds1"},
			},
			matches: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sel := epSelector(tc.in)

			ns := &slim_corev1.Namespace{ObjectMeta: slim_metav1.ObjectMeta{Name: tc.pod.Namespace}}
			pod := &slim_corev1.Pod{ObjectMeta: tc.pod}
			// This is the function used by other parts of the control plane to
			// get the labels for a pod.
			_, lbls, _, err := ciliumK8s.GetPodMetadata(ns, pod)
			if err != nil {
				t.Fatalf("Error getting pod metadata: %v", err)
			}
			// Labels need to be tagged as sourced from K8s.
			k8sLbls := ciliumLbls.Map2Labels(lbls, ciliumLbls.LabelSourceK8s).LabelArray()
			if got := sel.Matches(k8sLbls); got != tc.matches {
				t.Errorf("Selector %+v, Labels %+v. Matches() = %t, wanted %t", sel, k8sLbls, got, tc.matches)
			}
		})
	}
}

func TestParseFQDNNetworkPolicy(t *testing.T) {
	re.InitRegexCompileLRU(defaults.FQDNRegexCompileLRUSize)
	defaultLabels := []ciliumLbls.Label{
		{
			Key:    ciliumConst.PolicyLabelDerivedFrom,
			Value:  resourceTypeFQDNNetworkPolicy,
			Source: ciliumLbls.LabelSourceK8s,
		},
		{
			Key:    ciliumConst.PolicyLabelNamespace,
			Value:  "default",
			Source: ciliumLbls.LabelSourceK8s,
		},
		{
			Key:    ciliumConst.PolicyLabelName,
			Source: ciliumLbls.LabelSourceK8s,
		},
		{
			Key:    ciliumConst.PolicyLabelUID,
			Source: ciliumLbls.LabelSourceK8s,
		},
	}
	defaultNSSel := api.EndpointSelector{
		LabelSelector: &slim_metav1.LabelSelector{
			MatchLabels: k8sPrefix(map[string]string{
				ciliumConst.PodNamespaceLabel: "default",
			}),
		},
	}

	for _, tc := range []struct {
		desc string
		in   *v1alpha1.FQDNNetworkPolicy
		want *api.Rule
	}{
		{
			desc: "match name",
			in: &v1alpha1.FQDNNetworkPolicy{
				Spec: v1alpha1.FQDNNetworkPolicySpec{
					PodSelector: metav1.LabelSelector{},
					Egress: []v1alpha1.FQDNNetworkPolicyEgressRule{
						{
							Matches: []v1alpha1.FQDNNetworkPolicyMatch{
								{Name: "www.google.com"},
							},
						},
					},
				},
			},
			want: &api.Rule{
				EndpointSelector: defaultNSSel,
				Egress: []api.EgressRule{
					dnsProxyRedirect(),
					{
						ToFQDNs: []api.FQDNSelector{
							{MatchName: "www.google.com"},
						},
					},
				},
				Labels: defaultLabels,
			},
		},
		{
			desc: "match pattern with ports",
			in: &v1alpha1.FQDNNetworkPolicy{
				Spec: v1alpha1.FQDNNetworkPolicySpec{
					PodSelector: metav1.LabelSelector{},
					Egress: []v1alpha1.FQDNNetworkPolicyEgressRule{
						{
							Matches: []v1alpha1.FQDNNetworkPolicyMatch{
								{Pattern: "*.googleapis.com"},
							},
							Ports: []v1alpha1.FQDNNetworkPolicyPort{
								{Port: int32Ptr(80), Protocol: "TCP"},
								{Port: int32Ptr(53)},
								{Protocol: "UDP"},
							},
						},
					},
				},
			},
			want: &api.Rule{
				EndpointSelector: defaultNSSel,
				Egress: []api.EgressRule{
					dnsProxyRedirect(),
					{
						ToFQDNs: []api.FQDNSelector{
							{MatchPattern: "*.googleapis.com"},
						},
						ToPorts: []api.PortRule{{Ports: []api.PortProtocol{
							{Port: "80", Protocol: api.ProtoTCP},
							{Port: "53", Protocol: api.ProtoAny},
							{Port: "0", Protocol: api.ProtoUDP},
						}}},
					},
				},
				Labels: defaultLabels,
			},
		},
		{
			desc: "multiple egresses",
			in: &v1alpha1.FQDNNetworkPolicy{
				Spec: v1alpha1.FQDNNetworkPolicySpec{
					PodSelector: metav1.LabelSelector{},
					Egress: []v1alpha1.FQDNNetworkPolicyEgressRule{
						{
							Matches: []v1alpha1.FQDNNetworkPolicyMatch{
								{Pattern: "*.googleapis.com"},
							},
							Ports: []v1alpha1.FQDNNetworkPolicyPort{
								{Port: int32Ptr(443), Protocol: "TCP"},
							},
						},
						{
							Matches: []v1alpha1.FQDNNetworkPolicyMatch{
								{Name: "www.github.com"},
								{Name: "www.kubernetes.io"},
							},
						},
					},
				},
			},
			want: &api.Rule{
				EndpointSelector: defaultNSSel,
				Egress: []api.EgressRule{
					dnsProxyRedirect(),
					{
						ToFQDNs: []api.FQDNSelector{
							{MatchPattern: "*.googleapis.com"},
						},
						ToPorts: []api.PortRule{{Ports: []api.PortProtocol{
							{Port: "443", Protocol: api.ProtoTCP},
						}}},
					},
					{
						ToFQDNs: []api.FQDNSelector{
							{MatchName: "www.github.com"},
							{MatchName: "www.kubernetes.io"},
						},
					},
				},
				Labels: defaultLabels,
			},
		},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			got, err := parseFQDNNetworkPolicy(tc.in)
			if err != nil {
				t.Fatalf("ParseFQDNNetworkPolicy()=%v, want nil", err)
			}
			opts := cmp.Options{
				cmpopts.SortSlices(labelLess),
				cmpopts.IgnoreUnexported(api.EndpointSelector{}, api.EgressCommonRule{}),
			}
			if diff := cmp.Diff(tc.want, got, opts...); diff != "" {
				t.Fatalf("ParseFQDNNetworkPolicy() had a diff (-want, +got):\n%s", diff)
			}
		})
	}
}
