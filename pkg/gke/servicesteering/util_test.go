package servicesteering

import (
	"testing"

	ciliumio "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/u8proto"
	"github.com/google/go-cmp/cmp"
	v1 "gke-internal.googlesource.com/anthos-networking/apis/v2/service-steering/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
)

var simpleSubject v1.TrafficSelectorSubject = v1.TrafficSelectorSubject{
	Pods: v1.NamespacedPodsSubject{
		NamespaceSelector: metav1.LabelSelector{},
		PodSelector: metav1.LabelSelector{
			MatchLabels: map[string]string{
				"app": "proxy",
			},
		},
	},
}

func TestExtractCIDR(t *testing.T) {
	tests := []struct {
		name    string
		ts      *v1.TrafficSelector
		want    string
		wantErr bool
	}{
		{
			name: "egress /0",
			ts: &v1.TrafficSelector{Spec: v1.TrafficSelectorSpec{
				Egress: &v1.TrafficSelectorEgressRule{
					To:    peerFromCIDR("0.0.0.0/0"),
					Ports: []v1.TrafficSelectorPort{{AllPorts: &v1.AllPorts{Protocol: "TCP"}}},
				},
			}},
			want:    "0.0.0.0/0",
			wantErr: false,
		},
		{
			name: "missing CIDR",
			ts: &v1.TrafficSelector{Spec: v1.TrafficSelectorSpec{
				Egress: &v1.TrafficSelectorEgressRule{
					Ports: []v1.TrafficSelectorPort{{AllPorts: &v1.AllPorts{Protocol: "TCP"}}},
				},
			}},
			want:    "0.0.0.0/0",
			wantErr: false,
		},
		{
			name: "egress /32",
			ts: &v1.TrafficSelector{Spec: v1.TrafficSelectorSpec{
				Egress: &v1.TrafficSelectorEgressRule{
					To:    peerFromCIDR("10.0.0.1/32"),
					Ports: []v1.TrafficSelectorPort{{AllPorts: &v1.AllPorts{Protocol: "TCP"}}},
				},
			}},
			want:    "10.0.0.1/32",
			wantErr: false,
		},
		{
			name: "ingress /24",
			ts: &v1.TrafficSelector{Spec: v1.TrafficSelectorSpec{
				Ingress: &v1.TrafficSelectorIngressRule{
					From:  peerFromCIDR("172.0.0.0/24"),
					Ports: []v1.TrafficSelectorPort{{AllPorts: &v1.AllPorts{Protocol: "TCP"}}},
				},
			}},
			want:    "172.0.0.0/24",
			wantErr: false,
		},
		{
			name: "invalid CIDR",
			ts: &v1.TrafficSelector{Spec: v1.TrafficSelectorSpec{
				Egress: &v1.TrafficSelectorEgressRule{
					To:    peerFromCIDR("32.0.0.1"),
					Ports: []v1.TrafficSelectorPort{{AllPorts: &v1.AllPorts{Protocol: "TCP"}}},
				},
			}},
			wantErr: true,
		},
		{
			name:    "missing ingress and egress",
			ts:      &v1.TrafficSelector{Spec: v1.TrafficSelectorSpec{}},
			wantErr: true,
		},
		{
			name: "ingress and egress are set",
			ts: &v1.TrafficSelector{Spec: v1.TrafficSelectorSpec{
				Egress: &v1.TrafficSelectorEgressRule{
					To:    peerFromCIDR("10.0.0.1"),
					Ports: []v1.TrafficSelectorPort{{AllPorts: &v1.AllPorts{Protocol: "TCP"}}},
				},
				Ingress: &v1.TrafficSelectorIngressRule{
					From:  peerFromCIDR("10.0.0.1"),
					Ports: []v1.TrafficSelectorPort{{AllPorts: &v1.AllPorts{Protocol: "TCP"}}},
				},
			}},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			selector, err := newExtractedSelector(tt.ts)
			if (err != nil) != tt.wantErr {
				t.Errorf("extractCIDR() returns error = %v, wantErr %v", err, tt.wantErr)
			}
			if err != nil {
				return
			}
			got := selector.cidr.String()
			if diff := cmp.Diff(got, tt.want); diff != "" {
				t.Errorf("extractCIDR() returns unexpected output (-got, +want):\n%s", diff)
			}
		})
	}
}

func TestExtractPorts(t *testing.T) {
	tests := []struct {
		name    string
		ts      *v1.TrafficSelector
		want    map[portSelector]struct{}
		wantErr bool
	}{
		{
			name: "all TCP",
			ts: &v1.TrafficSelector{Spec: v1.TrafficSelectorSpec{
				Egress: &v1.TrafficSelectorEgressRule{
					Ports: []v1.TrafficSelectorPort{
						{AllPorts: &v1.AllPorts{Protocol: "TCP"}},
					},
				},
			}},
			want: map[portSelector]struct{}{
				{portNumber: 0, proto: u8proto.TCP}: exists,
			},
			wantErr: false,
		},
		{
			name: "all UDP",
			ts: &v1.TrafficSelector{Spec: v1.TrafficSelectorSpec{
				Egress: &v1.TrafficSelectorEgressRule{
					Ports: []v1.TrafficSelectorPort{
						{AllPorts: &v1.AllPorts{Protocol: "UDP"}},
					},
				},
			}},
			want: map[portSelector]struct{}{
				{portNumber: 0, proto: u8proto.UDP}: exists,
			},
			wantErr: false,
		},
		{
			name: "TCP (80, 443)",
			ts: &v1.TrafficSelector{Spec: v1.TrafficSelectorSpec{
				Egress: &v1.TrafficSelectorEgressRule{
					Ports: []v1.TrafficSelectorPort{
						{PortNumber: &v1.Port{Port: 80, Protocol: "TCP"}},
						{PortNumber: &v1.Port{Port: 443, Protocol: "TCP"}},
					},
				},
			}},
			want: map[portSelector]struct{}{
				{portNumber: 80, proto: u8proto.TCP}:  exists,
				{portNumber: 443, proto: u8proto.TCP}: exists,
			},
			wantErr: false,
		},
		{
			name: "unsupported protocol",
			ts: &v1.TrafficSelector{Spec: v1.TrafficSelectorSpec{
				Egress: &v1.TrafficSelectorEgressRule{
					Ports: []v1.TrafficSelectorPort{
						{PortNumber: &v1.Port{Port: 80, Protocol: "STCP"}},
					},
				},
			}},
			wantErr: true,
		},
		{
			name: "empty ports",
			ts: &v1.TrafficSelector{Spec: v1.TrafficSelectorSpec{
				Egress: &v1.TrafficSelectorEgressRule{},
			}},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			selector, err := newExtractedSelector(tt.ts)
			if (err != nil) != tt.wantErr {
				t.Errorf("extractPorts() returns error = %v, wantErr %v", err, tt.wantErr)
			}
			if err != nil {
				return
			}
			got := selector.portSelectors
			if diff := cmp.Diff(got, tt.want); diff != "" {
				t.Errorf("extractPorts() returns unexpected output (-got, +want):\n%s", diff)
			}
		})
	}
}

func TestExtractSubject(t *testing.T) {
	tests := []struct {
		name         string
		ts           *v1.TrafficSelector
		mustMatch    []labels.Set
		mustNotMatch []labels.Set
		wantErr      bool
	}{
		{
			name: "pod label selector",
			ts: selectorFromSubject(v1.NamespacedPodsSubject{PodSelector: metav1.LabelSelector{
				MatchLabels: map[string]string{
					"app": "proxy",
				},
			}}),
			mustMatch: []labels.Set{
				{"app": "proxy"},
			},
			mustNotMatch: []labels.Set{
				{},
			},
			wantErr: false,
		},
		{
			name: "pod expression selector",
			ts: selectorFromSubject(v1.NamespacedPodsSubject{PodSelector: metav1.LabelSelector{
				MatchExpressions: []metav1.LabelSelectorRequirement{
					{Key: "app", Operator: metav1.LabelSelectorOpDoesNotExist},
				},
			}}),
			mustMatch: []labels.Set{
				{},
			},
			mustNotMatch: []labels.Set{
				{"app": ""},
			},
			wantErr: false,
		},
		{
			name: "namespace label selector",
			ts: selectorFromSubject(v1.NamespacedPodsSubject{NamespaceSelector: metav1.LabelSelector{
				MatchLabels: map[string]string{
					"app": "proxy",
				},
			}}),
			mustMatch: []labels.Set{
				{policy.JoinPath(ciliumio.PodNamespaceMetaLabels, "app"): "proxy"},
			},
			mustNotMatch: []labels.Set{
				{},
				{"app": "proxy"},
				{policy.JoinPath(ciliumio.PodNamespaceMetaLabels, "app"): "not-proxy"},
			},
			wantErr: false,
		},
		{
			name: "invalid match expression",
			ts: selectorFromSubject(v1.NamespacedPodsSubject{PodSelector: metav1.LabelSelector{
				MatchExpressions: []metav1.LabelSelectorRequirement{
					{Key: "app", Operator: "bad-operator"},
				},
			}}),
			mustMatch:    []labels.Set{},
			mustNotMatch: []labels.Set{},
			wantErr:      true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			selector, err := newExtractedSelector(tt.ts)
			if (err != nil) != tt.wantErr {
				t.Errorf("extractSubject() returns error = %v, wantErr %v", err, tt.wantErr)
			}
			if err != nil {
				return
			}
			for _, labels := range tt.mustMatch {
				if err := selector.matchesLabels(labels); err != nil {
					t.Errorf(
						"expected {%v} to match namespace selector {%s} and pod selector {%s}, but got error: %v",
						labels,
						selector.nsSelector,
						selector.podSelector,
						err,
					)
				}
			}
			for _, labels := range tt.mustNotMatch {
				if err := selector.matchesLabels(labels); err == nil {
					t.Errorf(
						"expected {%v} to not match namespace selector {%s} and pod selector {%s}, but it does",
						labels,
						selector.nsSelector,
						selector.podSelector,
					)
				}
			}
		})
	}
}

func peerFromCIDR(cidr string) *v1.TrafficSelectorPeer {
	return &v1.TrafficSelectorPeer{
		IPBlock: &v1.TrafficSelectorIPBlock{
			CIDR: cidr,
		},
	}
}

func selectorFromSubject(subject v1.NamespacedPodsSubject) *v1.TrafficSelector {
	return &v1.TrafficSelector{
		Spec: v1.TrafficSelectorSpec{
			Subject: v1.TrafficSelectorSubject{
				Pods: subject,
			},
			Egress: &v1.TrafficSelectorEgressRule{
				Ports: []v1.TrafficSelectorPort{{AllPorts: &v1.AllPorts{Protocol: "TCP"}}},
			},
		},
	}
}
