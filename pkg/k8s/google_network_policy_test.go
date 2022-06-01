//go:build !privileged_tests
// +build !privileged_tests

package k8s

import (
	"fmt"
	"testing"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/checker"
	k8sConst "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	slim_networkingv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/networking/v1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/util/intstr"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/policy/api"
	networkv1 "gke-internal.googlesource.com/anthos-networking/apis/v2/network/v1"
)

var (
	vlanIngressCtx = policy.SearchContext{
		From: labels.LabelArray{
			labels.NewLabel(k8sConst.PodNamespaceLabel, slim_metav1.NamespaceDefault, labels.LabelSourceK8s),
			labels.NewLabel("foo3", "bar3", labels.LabelSourceK8s),
			labels.NewLabel("foo4", "bar4", labels.LabelSourceK8s),
			labels.NewLabel(networkv1.NetworkAnnotationKey, "vlan-network", labels.LabelSourceK8s),
		},
		To: labels.LabelArray{
			labels.NewLabel(k8sConst.PodNamespaceLabel, slim_metav1.NamespaceDefault, labels.LabelSourceK8s),
			labels.NewLabel("foo1", "bar1", labels.LabelSourceK8s),
			labels.NewLabel("foo2", "bar2", labels.LabelSourceK8s),
			labels.NewLabel(networkv1.NetworkAnnotationKey, "vlan-network", labels.LabelSourceK8s),
		},
		DPorts: []*models.Port{
			{
				Port:     443,
				Protocol: models.PortProtocolTCP,
			},
		},
		Trace: policy.TRACE_VERBOSE,
	}

	emptyNetworkIngressCtx = policy.SearchContext{
		From: labels.LabelArray{
			labels.NewLabel(k8sConst.PodNamespaceLabel, slim_metav1.NamespaceDefault, labels.LabelSourceK8s),
			labels.NewLabel("foo3", "bar3", labels.LabelSourceK8s),
			labels.NewLabel("foo4", "bar4", labels.LabelSourceK8s),
		},
		To: labels.LabelArray{
			labels.NewLabel(k8sConst.PodNamespaceLabel, slim_metav1.NamespaceDefault, labels.LabelSourceK8s),
			labels.NewLabel("foo1", "bar1", labels.LabelSourceK8s),
			labels.NewLabel("foo2", "bar2", labels.LabelSourceK8s),
		},
		DPorts: []*models.Port{
			{
				Port:     443,
				Protocol: models.PortProtocolTCP,
			},
		},
		Trace: policy.TRACE_VERBOSE,
	}

	podNetworkIngressCtx = policy.SearchContext{
		From: labels.LabelArray{
			labels.NewLabel(k8sConst.PodNamespaceLabel, slim_metav1.NamespaceDefault, labels.LabelSourceK8s),
			labels.NewLabel("foo3", "bar3", labels.LabelSourceK8s),
			labels.NewLabel("foo4", "bar4", labels.LabelSourceK8s),
			labels.NewLabel(networkv1.NetworkAnnotationKey, "pod-network", labels.LabelSourceK8s),
		},
		To: labels.LabelArray{
			labels.NewLabel(k8sConst.PodNamespaceLabel, slim_metav1.NamespaceDefault, labels.LabelSourceK8s),
			labels.NewLabel("foo1", "bar1", labels.LabelSourceK8s),
			labels.NewLabel("foo2", "bar2", labels.LabelSourceK8s),
			labels.NewLabel(networkv1.NetworkAnnotationKey, "pod-network", labels.LabelSourceK8s),
		},
		DPorts: []*models.Port{
			{
				Port:     443,
				Protocol: models.PortProtocolTCP,
			},
		},
		Trace: policy.TRACE_VERBOSE,
	}

	vlanEgressCtx = policy.SearchContext{
		From: labels.LabelArray{
			labels.NewLabel(k8sConst.PodNamespaceLabel, slim_metav1.NamespaceDefault, labels.LabelSourceK8s),
			labels.NewLabel("foo1", "bar1", labels.LabelSourceK8s),
			labels.NewLabel("foo2", "bar2", labels.LabelSourceK8s),
			labels.NewLabel(networkv1.NetworkAnnotationKey, "vlan-network", labels.LabelSourceK8s),
		},
		To: labels.LabelArray{
			labels.NewLabel(k8sConst.PodNamespaceLabel, slim_metav1.NamespaceDefault, labels.LabelSourceK8s),
			labels.NewLabel("foo3", "bar3", labels.LabelSourceK8s),
			labels.NewLabel("foo4", "bar4", labels.LabelSourceK8s),
			labels.NewLabel(networkv1.NetworkAnnotationKey, "vlan-network", labels.LabelSourceK8s),
		},
		DPorts: []*models.Port{
			{
				Port:     443,
				Protocol: models.PortProtocolTCP,
			},
		},
		Trace: policy.TRACE_VERBOSE,
	}

	emptyNetworkEgressCtx = policy.SearchContext{
		From: labels.LabelArray{
			labels.NewLabel(k8sConst.PodNamespaceLabel, slim_metav1.NamespaceDefault, labels.LabelSourceK8s),
			labels.NewLabel("foo1", "bar1", labels.LabelSourceK8s),
			labels.NewLabel("foo2", "bar2", labels.LabelSourceK8s),
		},
		To: labels.LabelArray{
			labels.NewLabel(k8sConst.PodNamespaceLabel, slim_metav1.NamespaceDefault, labels.LabelSourceK8s),
			labels.NewLabel("foo3", "bar3", labels.LabelSourceK8s),
			labels.NewLabel("foo4", "bar4", labels.LabelSourceK8s),
		},
		DPorts: []*models.Port{
			{
				Port:     443,
				Protocol: models.PortProtocolTCP,
			},
		},
		Trace: policy.TRACE_VERBOSE,
	}

	podNetworkEgressCtx = policy.SearchContext{
		From: labels.LabelArray{
			labels.NewLabel(k8sConst.PodNamespaceLabel, slim_metav1.NamespaceDefault, labels.LabelSourceK8s),
			labels.NewLabel("foo1", "bar1", labels.LabelSourceK8s),
			labels.NewLabel("foo2", "bar2", labels.LabelSourceK8s),
			labels.NewLabel(networkv1.NetworkAnnotationKey, "pod-network", labels.LabelSourceK8s),
		},
		To: labels.LabelArray{
			labels.NewLabel(k8sConst.PodNamespaceLabel, slim_metav1.NamespaceDefault, labels.LabelSourceK8s),
			labels.NewLabel("foo3", "bar3", labels.LabelSourceK8s),
			labels.NewLabel("foo4", "bar4", labels.LabelSourceK8s),
			labels.NewLabel(networkv1.NetworkAnnotationKey, "pod-network", labels.LabelSourceK8s),
		},
		DPorts: []*models.Port{
			{
				Port:     443,
				Protocol: models.PortProtocolTCP,
			},
		},
		Trace: policy.TRACE_VERBOSE,
	}

	ingressNetworkPolicyWithNetworkAnnotation = slim_networkingv1.NetworkPolicy{
		ObjectMeta: slim_metav1.ObjectMeta{
			Annotations: map[string]string{
				networkv1.NetworkAnnotationKey: "pod-network",
			},
		},
		Spec: slim_networkingv1.NetworkPolicySpec{
			PodSelector: slim_metav1.LabelSelector{
				MatchLabels: map[string]string{
					"foo1": "bar1",
					"foo2": "bar2",
				},
			},
			Ingress: []slim_networkingv1.NetworkPolicyIngressRule{
				{
					From: []slim_networkingv1.NetworkPolicyPeer{
						{
							PodSelector: &slim_metav1.LabelSelector{
								MatchLabels: map[string]string{
									"foo3": "bar3",
									"foo4": "bar4",
								},
							},
						},
					},
					Ports: []slim_networkingv1.NetworkPolicyPort{
						{
							Port: &intstr.IntOrString{
								Type:   intstr.Int,
								IntVal: 443,
							},
						},
					},
				},
			},
		},
	}

	ingressNetworkPolicyWithEmptyNetworkAnnotation = slim_networkingv1.NetworkPolicy{
		Spec: slim_networkingv1.NetworkPolicySpec{
			PodSelector: slim_metav1.LabelSelector{
				MatchLabels: map[string]string{
					"foo1": "bar1",
					"foo2": "bar2",
				},
			},
			Ingress: []slim_networkingv1.NetworkPolicyIngressRule{
				{
					From: []slim_networkingv1.NetworkPolicyPeer{
						{
							PodSelector: &slim_metav1.LabelSelector{
								MatchLabels: map[string]string{
									"foo3": "bar3",
									"foo4": "bar4",
								},
							},
						},
					},
					Ports: []slim_networkingv1.NetworkPolicyPort{
						{
							Port: &intstr.IntOrString{
								Type:   intstr.Int,
								IntVal: 443,
							},
						},
					},
				},
			},
		},
	}

	egressNetworkPolicyWithNetworkAnnotation = slim_networkingv1.NetworkPolicy{
		ObjectMeta: slim_metav1.ObjectMeta{
			Annotations: map[string]string{
				networkv1.NetworkAnnotationKey: "pod-network",
			},
		},
		Spec: slim_networkingv1.NetworkPolicySpec{
			PodSelector: slim_metav1.LabelSelector{
				MatchLabels: map[string]string{
					"foo1": "bar1",
					"foo2": "bar2",
				},
			},
			Egress: []slim_networkingv1.NetworkPolicyEgressRule{
				{
					To: []slim_networkingv1.NetworkPolicyPeer{
						{
							PodSelector: &slim_metav1.LabelSelector{
								MatchLabels: map[string]string{
									"foo3": "bar3",
									"foo4": "bar4",
								},
							},
						},
					},
					Ports: []slim_networkingv1.NetworkPolicyPort{
						{
							Port: &intstr.IntOrString{
								Type:   intstr.Int,
								IntVal: 443,
							},
						},
					},
				},
			},
		},
	}

	egressNetworkPolicyWithEmptyNetworkAnnotation = slim_networkingv1.NetworkPolicy{
		Spec: slim_networkingv1.NetworkPolicySpec{
			PodSelector: slim_metav1.LabelSelector{
				MatchLabels: map[string]string{
					"foo1": "bar1",
					"foo2": "bar2",
				},
			},
			Egress: []slim_networkingv1.NetworkPolicyEgressRule{
				{
					To: []slim_networkingv1.NetworkPolicyPeer{
						{
							PodSelector: &slim_metav1.LabelSelector{
								MatchLabels: map[string]string{
									"foo3": "bar3",
									"foo4": "bar4",
								},
							},
						},
					},
					Ports: []slim_networkingv1.NetworkPolicyPort{
						{
							Port: &intstr.IntOrString{
								Type:   intstr.Int,
								IntVal: 443,
							},
						},
					},
				},
			},
		},
	}
)

func Test_parseNetworkPolicyIngressForNetworkSelectorWithMultiNicEnabled(t *testing.T) {
	option.Config.EnableGoogleMultiNIC = true
	defer func() { option.Config.EnableGoogleMultiNIC = false }()

	tests := []struct {
		name          string
		networkPolicy *slim_networkingv1.NetworkPolicy
		ctx           *policy.SearchContext
		want          api.Decision
	}{
		{
			name:          "test-pod-network-np-for-ingress-on-pod-network-from-vlan-network",
			networkPolicy: &ingressNetworkPolicyWithNetworkAnnotation,
			ctx:           &vlanIngressCtx,
			want:          api.Denied, // ctx has the wrong value for network annotation key, should not be allowed explicitly by this networkpolicy
		},
		{
			name:          "test-pod-network-np-for-ingress-on-pod-network-from-empty-network",
			networkPolicy: &ingressNetworkPolicyWithNetworkAnnotation,
			ctx:           &emptyNetworkIngressCtx,
			want:          api.Denied, // ctx is missing network annotation label, should not be allowed explicitly by this networkpolicy
		},
		{
			name:          "test-pod-network-np-for-ingress-on-pod-network-from-pod-network",
			networkPolicy: &ingressNetworkPolicyWithNetworkAnnotation,
			ctx:           &podNetworkIngressCtx,
			want:          api.Allowed, // valid ctx, should be allowed by this networkpolicy
		},
		{
			name:          "test-empty-network-np-for-ingress-on-pod-network-from-vlan-network",
			networkPolicy: &ingressNetworkPolicyWithEmptyNetworkAnnotation,
			ctx:           &vlanIngressCtx,
			want:          api.Allowed, // presence of network annotation label is irrelvant as networkSelector is nil, should be allowed
		},
		{
			name:          "test-empty-network-np-for-ingress-on-pod-network-from-empty-network",
			networkPolicy: &ingressNetworkPolicyWithEmptyNetworkAnnotation,
			ctx:           &emptyNetworkIngressCtx,
			want:          api.Allowed, // absence of network annotation label is irrelvant as networkSelector is nil, should be allowed
		},
		{
			name:          "test-empty-network-np-for-ingress-on-pod-network-from-pod-network",
			networkPolicy: &ingressNetworkPolicyWithEmptyNetworkAnnotation,
			ctx:           &podNetworkIngressCtx,
			want:          api.Allowed, // presence of network annotation label is irrelvant as networkSelector is nil, should be allowed
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rules, err := ParseNetworkPolicy(tt.networkPolicy)
			if err != nil {
				t.Fatalf("Got error %s while attempting to parseNetworkPolicy for networkPolicy: %+v\n", err.Error(), tt.networkPolicy)
			}
			repo := testNewPolicyRepository()
			repo.AddList(rules)
			if got := repo.AllowsIngressRLocked(tt.ctx); got != tt.want {
				t.Fatalf("Policy verdict mismatch, got %s, want %s", got.String(), tt.want.String())
			}
		})
	}
}

func Test_parseNetworkPolicyEgressForNetworkSelectorWithMultiNicEnabled(t *testing.T) {
	option.Config.EnableGoogleMultiNIC = true
	defer func() { option.Config.EnableGoogleMultiNIC = false }()

	tests := []struct {
		name          string
		networkPolicy *slim_networkingv1.NetworkPolicy
		ctx           *policy.SearchContext
		want          api.Decision
	}{
		{
			name:          "test-pod-network-np-for-egress-on-pod-network-from-vlan-network",
			networkPolicy: &egressNetworkPolicyWithNetworkAnnotation,
			ctx:           &vlanEgressCtx,
			want:          api.Denied, // ctx has the wrong value for network annotation key, should not be allowed explicitly by this networkpolicy
		},
		{
			name:          "test-pod-network-np-for-egress-on-pod-network-from-empty-network",
			networkPolicy: &egressNetworkPolicyWithNetworkAnnotation,
			ctx:           &emptyNetworkEgressCtx,
			want:          api.Denied, // ctx is missing network annotation label, should not be allowed explicitly by this networkpolicy
		},
		{
			name:          "test-pod-network-np-for-egress-on-pod-network-from-pod-network",
			networkPolicy: &egressNetworkPolicyWithNetworkAnnotation,
			ctx:           &podNetworkEgressCtx,
			want:          api.Allowed, // valid ctx, should be allowed by this networkpolicy
		},
		{
			name:          "test-empty-network-np-for-egress-on-pod-network-from-vlan-network",
			networkPolicy: &egressNetworkPolicyWithEmptyNetworkAnnotation,
			ctx:           &vlanEgressCtx,
			want:          api.Allowed, // presence of network annotation label is irrelvant as networkSelector is nil, should be allowed
		},
		{
			name:          "test-empty-network-np-for-egress-on-pod-network-from-empty-network",
			networkPolicy: &egressNetworkPolicyWithEmptyNetworkAnnotation,
			ctx:           &emptyNetworkEgressCtx,
			want:          api.Allowed, // absence of network annotation label is irrelvant as networkSelector is nil, should be allowed
		},
		{
			name:          "test-empty-network-np-for-egress-on-pod-network-from-pod-network",
			networkPolicy: &egressNetworkPolicyWithEmptyNetworkAnnotation,
			ctx:           &podNetworkEgressCtx,
			want:          api.Allowed, // presence of network annotation label is irrelvant as networkSelector is nil, should be allowed
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rules, err := ParseNetworkPolicy(tt.networkPolicy)
			if err != nil {
				t.Fatalf("Got error %s while attempting to parseNetworkPolicy for networkPolicy: %+v\n", err.Error(), tt.networkPolicy)
			}
			repo := testNewPolicyRepository()
			repo.AddList(rules)
			if got := repo.AllowsEgressRLocked(tt.ctx); got != tt.want {
				t.Fatalf("Policy verdict mismatch, got %s, want %s", got.String(), tt.want.String())
			}
		})
	}
}

func Test_parseNetworkPolicyIngressForNetworkSelectorWithMultiNicDisabled(t *testing.T) {
	tests := []struct {
		name          string
		networkPolicy *slim_networkingv1.NetworkPolicy
		ctx           *policy.SearchContext
		want          api.Decision
	}{
		{
			name:          "test-pod-network-np-for-ingress-on-pod-network-from-vlan-network-when-multiNic-is-disabled",
			networkPolicy: &ingressNetworkPolicyWithNetworkAnnotation,
			ctx:           &vlanIngressCtx,
			want:          api.Allowed, // multinic is disabled, presence of network annotation label is irrelvant as networkSelector is nil, should be allowed
		},
		{
			name:          "test-pod-network-np-for-ingress-on-pod-network-from-empty-network-when-multiNic-is-disabled",
			networkPolicy: &ingressNetworkPolicyWithNetworkAnnotation,
			ctx:           &emptyNetworkIngressCtx,
			want:          api.Allowed, // multinic is disabled, absence of network annotation label is irrelvant as networkSelector is nil, should be allowed
		},
		{
			name:          "test-pod-network-np-for-ingress-on-pod-network-from-pod-network-when-multiNic-is-disabled",
			networkPolicy: &ingressNetworkPolicyWithNetworkAnnotation,
			ctx:           &podNetworkIngressCtx,
			want:          api.Allowed, // multinic is disabled, presence of network annotation label is irrelvant as networkSelector is nil, should be allowed
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rules, err := ParseNetworkPolicy(tt.networkPolicy)
			if err != nil {
				t.Fatalf("Got error %s while attempting to parseNetworkPolicy for networkPolicy: %+v\n", err.Error(), tt.networkPolicy)
			}
			repo := testNewPolicyRepository()
			repo.AddList(rules)
			if got := repo.AllowsIngressRLocked(tt.ctx); got != tt.want {
				t.Fatalf("Policy verdict mismatch, got %s, want %s", got.String(), tt.want.String())
			}
		})
	}
}

func Test_parseNetworkPolicyEgressForNetworkSelectorWithMultiNicDisabled(t *testing.T) {
	tests := []struct {
		name          string
		networkPolicy *slim_networkingv1.NetworkPolicy
		ctx           *policy.SearchContext
		want          api.Decision
	}{
		{
			name:          "test-pod-network-np-for-egress-on-pod-network-from-vlan-network-when-multiNic-is-disabled",
			networkPolicy: &egressNetworkPolicyWithNetworkAnnotation,
			ctx:           &vlanEgressCtx,
			want:          api.Allowed, // multinic is disabled, presence of network annotation label is irrelvant as networkSelector is nil, should be allowed
		},
		{
			name:          "test-pod-network-np-for-egress-on-pod-network-from-empty-network-when-multiNic-is-disabled",
			networkPolicy: &egressNetworkPolicyWithNetworkAnnotation,
			ctx:           &emptyNetworkEgressCtx,
			want:          api.Allowed, // multinic is disabled, absence of network annotation label is irrelvant as networkSelector is nil, should be allowed
		},
		{
			name:          "test-pod-network-np-for-egress-on-pod-network-from-pod-network-when-multiNic-is-disabled",
			networkPolicy: &egressNetworkPolicyWithNetworkAnnotation,
			ctx:           &podNetworkEgressCtx,
			want:          api.Allowed, // multinic is disabled, presence of network annotation label is irrelvant as networkSelector is nil, should be allowed
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rules, err := ParseNetworkPolicy(tt.networkPolicy)
			if err != nil {
				t.Fatalf("Got error %s while attempting to parseNetworkPolicy for networkPolicy: %+v\n", err.Error(), tt.networkPolicy)
			}
			repo := testNewPolicyRepository()
			repo.AddList(rules)
			if got := repo.AllowsEgressRLocked(tt.ctx); got != tt.want {
				t.Fatalf("Policy verdict mismatch, got %s, want %s", got.String(), tt.want.String())
			}
		})
	}
}

func Test_parseNetworkPolicyIngressAllowAllForNetworkSelector(t *testing.T) {
	option.Config.EnableGoogleMultiNIC = true
	defer func() { option.Config.EnableGoogleMultiNIC = false }()

	allowAllIngressNP := &slim_networkingv1.NetworkPolicy{
		Spec: slim_networkingv1.NetworkPolicySpec{
			PodSelector: slim_metav1.LabelSelector{},
			Ingress: []slim_networkingv1.NetworkPolicyIngressRule{
				{
					From: []slim_networkingv1.NetworkPolicyPeer{},
				},
			},
		},
	}

	allowAllIngressNPOnPodNetwork := &slim_networkingv1.NetworkPolicy{
		ObjectMeta: slim_metav1.ObjectMeta{
			Annotations: map[string]string{
				networkv1.NetworkAnnotationKey: "pod-network",
			},
		},
		Spec: slim_networkingv1.NetworkPolicySpec{
			PodSelector: slim_metav1.LabelSelector{},
			Ingress: []slim_networkingv1.NetworkPolicyIngressRule{
				{
					From: []slim_networkingv1.NetworkPolicyPeer{},
				},
			},
		},
	}

	tests := []struct {
		name          string
		networkPolicy *slim_networkingv1.NetworkPolicy
		ctx           *policy.SearchContext
		want          api.Decision
	}{
		{
			name:          "test-allow-all-ingress-np-for-ingress-on-vlan-network",
			networkPolicy: allowAllIngressNP,
			ctx:           &vlanIngressCtx,
			want:          api.Allowed, // Allows traffic from everywhere
		},
		{
			name:          "test-allow-all-ingress-np-for-ingress-no-network",
			networkPolicy: allowAllIngressNP,
			ctx:           &emptyNetworkIngressCtx,
			want:          api.Allowed, // Allows traffic from everywhere
		},
		{
			name:          "test-allow-all-ingress-np-for-ingress-on-pod-network",
			networkPolicy: allowAllIngressNP,
			ctx:           &podNetworkIngressCtx,
			want:          api.Allowed, // Allows traffic from everywhere
		},
		{
			name:          "test-allow-all-ingress-np-on-pod-network-for-ingress-on-vlan-network",
			networkPolicy: allowAllIngressNPOnPodNetwork,
			ctx:           &vlanIngressCtx,
			want:          api.Denied, // ctx has the wrong value for network annotation key, should not be allowed explicitly by this networkpolicy
		},
		{
			name:          "test-allow-all-ingress-np-on-pod-network-for-ingress-no-network",
			networkPolicy: allowAllIngressNPOnPodNetwork,
			ctx:           &emptyNetworkIngressCtx,
			want:          api.Denied, // ctx is missing network annotation label, should not be allowed explicitly by this networkpolicy
		},
		{
			name:          "test-allow-all-ingress-np-on-pod-network-for-ingress-on-pod-network",
			networkPolicy: allowAllIngressNPOnPodNetwork,
			ctx:           &podNetworkIngressCtx,
			want:          api.Allowed, // Allows all traffic on pod-network
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rules, err := ParseNetworkPolicy(tt.networkPolicy)
			if err != nil {
				t.Fatalf("Got error %s while attempting to parseNetworkPolicy for networkPolicy: %+v\n", err.Error(), tt.networkPolicy)
			}
			repo := testNewPolicyRepository()
			repo.AddList(rules)
			if got := repo.AllowsIngressRLocked(tt.ctx); got != tt.want {
				t.Fatalf("Policy verdict mismatch, got %s, want %s", got.String(), tt.want.String())
			}
		})
	}

}

func Test_parseNetworkPolicyEgressAllowAllForNetworkSelector(t *testing.T) {
	option.Config.EnableGoogleMultiNIC = true
	defer func() { option.Config.EnableGoogleMultiNIC = false }()

	allowAllEgressNP := &slim_networkingv1.NetworkPolicy{
		Spec: slim_networkingv1.NetworkPolicySpec{
			PodSelector: slim_metav1.LabelSelector{},
			Egress: []slim_networkingv1.NetworkPolicyEgressRule{
				{
					To: []slim_networkingv1.NetworkPolicyPeer{},
				},
			},
		},
	}

	allowAllEgressNPOnPodNetwork := &slim_networkingv1.NetworkPolicy{
		ObjectMeta: slim_metav1.ObjectMeta{
			Annotations: map[string]string{
				networkv1.NetworkAnnotationKey: "pod-network",
			},
		},
		Spec: slim_networkingv1.NetworkPolicySpec{
			PodSelector: slim_metav1.LabelSelector{},
			Egress: []slim_networkingv1.NetworkPolicyEgressRule{
				{
					To: []slim_networkingv1.NetworkPolicyPeer{},
				},
			},
		},
	}

	tests := []struct {
		name          string
		networkPolicy *slim_networkingv1.NetworkPolicy
		ctx           *policy.SearchContext
		want          api.Decision
	}{
		{
			name:          "test-allow-all-egress-np-for-egress-to-vlan-network",
			networkPolicy: allowAllEgressNP,
			ctx:           &vlanEgressCtx,
			want:          api.Allowed, // Allows traffic to everywhere
		},
		{
			name:          "test-allow-all-egress-np-for-egress-no-network",
			networkPolicy: allowAllEgressNP,
			ctx:           &emptyNetworkEgressCtx,
			want:          api.Allowed, // Allows traffic to everywhere
		},
		{
			name:          "test-allow-all-egress-np-for-egress-to-pod-network",
			networkPolicy: allowAllEgressNP,
			ctx:           &podNetworkEgressCtx,
			want:          api.Allowed, // Allows traffic to everywhere
		},
		{
			name:          "test-allow-all-egress-np-on-pod-network-for-egress-to-vlan-network",
			networkPolicy: allowAllEgressNPOnPodNetwork,
			ctx:           &vlanEgressCtx,
			want:          api.Denied, // ctx has the wrong value for network annotation key, should not be allowed explicitly by this networkpolicy
		},
		{
			name:          "test-allow-all-egress-np-on-pod-network-for-egress-no-network",
			networkPolicy: allowAllEgressNPOnPodNetwork,
			ctx:           &emptyNetworkEgressCtx,
			want:          api.Denied, // ctx is missing network annotation label, should not be allowed explicitly by this networkpolicy
		},
		{
			name:          "test-allow-all-egress-np-on-pod-network-for-egress-to-pod-network",
			networkPolicy: allowAllEgressNPOnPodNetwork,
			ctx:           &podNetworkEgressCtx,
			want:          api.Allowed, // Allows all traffic to pod-network
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rules, err := ParseNetworkPolicy(tt.networkPolicy)
			if err != nil {
				t.Fatalf("Got error %s while attempting to parseNetworkPolicy for networkPolicy: %+v\n", err.Error(), tt.networkPolicy)
			}
			repo := testNewPolicyRepository()
			repo.AddList(rules)
			if got := repo.AllowsEgressRLocked(tt.ctx); got != tt.want {
				t.Fatalf("Policy verdict mismatch, got %s, want %s", got.String(), tt.want.String())
			}
		})
	}

}

func Test_parseNetworkPolicyIngressDenyAllForNetworkSelector(t *testing.T) {
	option.Config.EnableGoogleMultiNIC = true
	defer func() { option.Config.EnableGoogleMultiNIC = false }()

	denyAllIngressNP := &slim_networkingv1.NetworkPolicy{
		Spec: slim_networkingv1.NetworkPolicySpec{
			PodSelector: slim_metav1.LabelSelector{},
		},
	}

	denyAllIngressNPOnPodNetwork := &slim_networkingv1.NetworkPolicy{
		ObjectMeta: slim_metav1.ObjectMeta{
			Annotations: map[string]string{
				networkv1.NetworkAnnotationKey: "pod-network",
			},
		},
		Spec: slim_networkingv1.NetworkPolicySpec{
			PodSelector: slim_metav1.LabelSelector{},
		},
	}

	tests := []struct {
		name          string
		networkPolicy *slim_networkingv1.NetworkPolicy
		ctx           *policy.SearchContext
		want          api.Decision
	}{
		{
			name:          "test-deny-all-ingress-np-for-ingress-on-vlan-network",
			networkPolicy: denyAllIngressNP,
			ctx:           &vlanIngressCtx,
			want:          api.Denied, // Denies traffic from everywhere
		},
		{
			name:          "test-deny-all-ingress-np-for-ingress-no-network",
			networkPolicy: denyAllIngressNP,
			ctx:           &emptyNetworkIngressCtx,
			want:          api.Denied, // Denies traffic from everywhere
		},
		{
			name:          "test-deny-all-ingress-np-for-ingress-on-pod-network",
			networkPolicy: denyAllIngressNP,
			ctx:           &podNetworkIngressCtx,
			want:          api.Denied, // Denies traffic from everywhere
		},
		{
			name:          "test-deny-all-ingress-np-on-pod-network-for-ingress-on-vlan-network",
			networkPolicy: denyAllIngressNPOnPodNetwork,
			ctx:           &vlanIngressCtx,
			want:          api.Denied, // policy has no explicit allow for vlan-network, hence denied
		},
		{
			name:          "test-deny-all-ingress-np-on-pod-network-for-ingress-no-network",
			networkPolicy: denyAllIngressNPOnPodNetwork,
			ctx:           &emptyNetworkIngressCtx,
			want:          api.Denied, // no explicit allow exist, hence denied
		},
		{
			name:          "test-deny-all-ingress-np-on-pod-network-for-ingress-on-pod-network",
			networkPolicy: denyAllIngressNPOnPodNetwork,
			ctx:           &podNetworkIngressCtx,
			want:          api.Denied, // Denies all traffic on pod-network
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rules, err := ParseNetworkPolicy(tt.networkPolicy)
			if err != nil {
				t.Fatalf("Got error %s while attempting to parseNetworkPolicy for networkPolicy: %+v\n", err.Error(), tt.networkPolicy)
			}
			repo := testNewPolicyRepository()
			repo.AddList(rules)
			if got := repo.AllowsIngressRLocked(tt.ctx); got != tt.want {
				t.Fatalf("Policy verdict mismatch, got %s, want %s", got.String(), tt.want.String())
			}
		})
	}

}

func Test_parseNetworkPolicyEgressDenyAllForNetworkSelector(t *testing.T) {
	option.Config.EnableGoogleMultiNIC = true
	defer func() { option.Config.EnableGoogleMultiNIC = false }()

	denyAllEgressNP := &slim_networkingv1.NetworkPolicy{
		Spec: slim_networkingv1.NetworkPolicySpec{
			PodSelector: slim_metav1.LabelSelector{},
		},
	}

	denyAllEgressNPOnPodNetwork := &slim_networkingv1.NetworkPolicy{
		ObjectMeta: slim_metav1.ObjectMeta{
			Annotations: map[string]string{
				networkv1.NetworkAnnotationKey: "pod-network",
			},
		},
		Spec: slim_networkingv1.NetworkPolicySpec{
			PodSelector: slim_metav1.LabelSelector{},
		},
	}

	tests := []struct {
		name          string
		networkPolicy *slim_networkingv1.NetworkPolicy
		ctx           *policy.SearchContext
		want          api.Decision
	}{
		{
			name:          "test-deny-all-egress-np-for-egress-to-vlan-network",
			networkPolicy: denyAllEgressNP,
			ctx:           &vlanEgressCtx,
			want:          api.Denied, // Denies traffic to everywhere
		},
		{
			name:          "test-deny-all-egress-np-for-egress-no-network",
			networkPolicy: denyAllEgressNP,
			ctx:           &emptyNetworkEgressCtx,
			want:          api.Denied, // Denies traffic to everywhere
		},
		{
			name:          "test-deny-all-egress-np-for-egress-to-pod-network",
			networkPolicy: denyAllEgressNP,
			ctx:           &podNetworkEgressCtx,
			want:          api.Denied, // Denies traffic to everywhere
		},
		{
			name:          "test-deny-all-egress-np-on-pod-network-for-egress-to-vlan-network",
			networkPolicy: denyAllEgressNPOnPodNetwork,
			ctx:           &vlanEgressCtx,
			want:          api.Denied, // policy has no explicit allow to vlan-network, hence denied
		},
		{
			name:          "test-deny-all-egress-np-on-pod-network-for-egress-no-network",
			networkPolicy: denyAllEgressNPOnPodNetwork,
			ctx:           &emptyNetworkEgressCtx,
			want:          api.Denied, // no explicit allow exist, hence denied
		},
		{
			name:          "test-deny-all-egress-np-on-pod-network-for-egress-to-pod-network",
			networkPolicy: denyAllEgressNPOnPodNetwork,
			ctx:           &podNetworkEgressCtx,
			want:          api.Denied, // Denies all traffic to pod-network
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rules, err := ParseNetworkPolicy(tt.networkPolicy)
			if err != nil {
				t.Fatalf("Got error %s while attempting to parseNetworkPolicy for networkPolicy: %+v\n", err.Error(), tt.networkPolicy)
			}
			repo := testNewPolicyRepository()
			repo.AddList(rules)
			if got := repo.AllowsEgressRLocked(tt.ctx); got != tt.want {
				t.Fatalf("Policy verdict mismatch, got %s, want %s", got.String(), tt.want.String())
			}
		})
	}

}

func Test_parseNetworkPolicyPeerForNetworkSelector(t *testing.T) {

	tests := []struct {
		name            string
		namespace       string
		peer            *slim_networkingv1.NetworkPolicyPeer
		networkSelector *slim_metav1.LabelSelector
		want            *api.EndpointSelector
	}{
		{
			name:      "peer-with-pod-selector-and-network-selector",
			namespace: "foo-namespace",
			peer: &slim_networkingv1.NetworkPolicyPeer{
				PodSelector: &slim_metav1.LabelSelector{
					MatchLabels: map[string]string{
						"foo": "bar",
					},
					MatchExpressions: []slim_metav1.LabelSelectorRequirement{
						{
							Key:      "foo",
							Operator: slim_metav1.LabelSelectorOpIn,
							Values:   []string{"bar", "baz"},
						},
					},
				},
			},
			networkSelector: &slim_metav1.LabelSelector{
				MatchLabels: map[string]string{
					"network-annotation-key": "pod-network",
				},
			},
			want: getSelectorPointer(
				api.NewESFromMatchRequirements(
					map[string]string{
						"k8s.foo":                         "bar",
						"k8s.io.kubernetes.pod.namespace": "foo-namespace",
						"k8s.network-annotation-key":      "pod-network",
					},
					[]slim_metav1.LabelSelectorRequirement{
						{
							Key:      "k8s.foo",
							Operator: slim_metav1.LabelSelectorOpIn,
							Values:   []string{"bar", "baz"},
						},
					},
				),
			),
		},
		{
			name:      "peer-nil-with-network-selector",
			namespace: "foo-namespace",
			networkSelector: &slim_metav1.LabelSelector{
				MatchLabels: map[string]string{
					"network-annotation-key": "pod-network",
				},
			},
			want: nil,
		},
		{
			name:      "peer-with-pod-selector-ns-selector-and-network-selector",
			namespace: "foo-namespace",
			peer: &slim_networkingv1.NetworkPolicyPeer{
				PodSelector: &slim_metav1.LabelSelector{
					MatchLabels: map[string]string{
						"foo": "bar",
					},
					MatchExpressions: []slim_metav1.LabelSelectorRequirement{
						{
							Key:      "foo",
							Operator: slim_metav1.LabelSelectorOpIn,
							Values:   []string{"bar", "baz"},
						},
					},
				},
				NamespaceSelector: &slim_metav1.LabelSelector{
					MatchLabels: map[string]string{
						"ns-foo": "ns-bar",
					},
					MatchExpressions: []slim_metav1.LabelSelectorRequirement{
						{
							Key:      "ns-foo-expression",
							Operator: slim_metav1.LabelSelectorOpExists,
						},
					},
				},
			},
			networkSelector: &slim_metav1.LabelSelector{
				MatchLabels: map[string]string{
					"network-annotation-key": "pod-network",
				},
			},
			want: getSelectorPointer(
				api.NewESFromMatchRequirements(
					map[string]string{
						"k8s.foo": "bar",
						"k8s.io.cilium.k8s.namespace.labels.ns-foo": "ns-bar",
						"k8s.network-annotation-key":                "pod-network",
					},
					[]slim_metav1.LabelSelectorRequirement{
						{
							Key:      "k8s.io.cilium.k8s.namespace.labels.ns-foo-expression",
							Operator: slim_metav1.LabelSelectorOpExists,
						},
						{
							Key:      "k8s.foo",
							Operator: slim_metav1.LabelSelectorOpIn,
							Values:   []string{"bar", "baz"},
						},
					},
				),
			),
		},
		{
			name:      "peer-with-ns-selector-and-network-selector",
			namespace: "foo-namespace",
			peer: &slim_networkingv1.NetworkPolicyPeer{
				NamespaceSelector: &slim_metav1.LabelSelector{
					MatchLabels: map[string]string{
						"ns-foo": "ns-bar",
					},
					MatchExpressions: []slim_metav1.LabelSelectorRequirement{
						{
							Key:      "ns-foo-expression",
							Operator: slim_metav1.LabelSelectorOpExists,
						},
					},
				},
			},
			networkSelector: &slim_metav1.LabelSelector{
				MatchLabels: map[string]string{
					"network-annotation-key": "vlan-network",
				},
			},
			want: getSelectorPointer(
				api.NewESFromMatchRequirements(
					map[string]string{
						"k8s.io.cilium.k8s.namespace.labels.ns-foo": "ns-bar",
						"k8s.network-annotation-key":                "vlan-network",
					},
					[]slim_metav1.LabelSelectorRequirement{
						{
							Key:      "k8s.io.cilium.k8s.namespace.labels.ns-foo-expression",
							Operator: slim_metav1.LabelSelectorOpExists,
						},
					},
				),
			),
		},
		{
			name:      "peer-with-allow-all-ns-selector-and-network-selector",
			namespace: "foo-namespace",
			peer: &slim_networkingv1.NetworkPolicyPeer{
				NamespaceSelector: &slim_metav1.LabelSelector{},
			},
			networkSelector: &slim_metav1.LabelSelector{
				MatchLabels: map[string]string{
					"network-annotation-key": "pod-network",
				},
			},
			want: getSelectorPointer(
				api.NewESFromMatchRequirements(
					map[string]string{
						"k8s.network-annotation-key": "pod-network",
					},
					[]slim_metav1.LabelSelectorRequirement{
						{
							Key:      fmt.Sprintf("%s.%s", labels.LabelSourceK8s, k8sConst.PodNamespaceLabel),
							Operator: slim_metav1.LabelSelectorOpExists,
						},
					},
				),
			),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseNetworkPolicyPeer(tt.namespace, tt.peer, tt.networkSelector)
			args := []interface{}{got, tt.want}
			names := []string{"obtained", "expected"}
			if equal, err := checker.DeepEquals.Check(args, names); !equal {
				t.Fatalf("Failed to parseNetworkPolicyPeer():\n%s", err)
			}
		})
	}
}
