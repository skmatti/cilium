package egressgateway

import (
	"testing"

	k8slbls "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/labels"
	networkv1 "k8s.io/cloud-provider-gcp/crd/apis/network/v1"
)

func TestSkipEgressNATPolicy(t *testing.T) {
	testcases := []struct {
		desc     string
		epLabels k8slbls.Labels
		want     bool
	}{
		{
			desc:     "empty labels",
			epLabels: k8slbls.Set{},
		},
		{
			desc: "empty network",
			epLabels: k8slbls.Set{
				networkv1.NetworkAnnotationKey: "",
			},
		},
		{
			desc: "pod-network network",
			epLabels: k8slbls.Set{
				networkv1.NetworkAnnotationKey: "pod-network",
			},
		},
		{
			desc: "default network",
			epLabels: k8slbls.Set{
				networkv1.NetworkAnnotationKey: "default",
			},
		},
		{
			desc: "default-vpc network",
			epLabels: k8slbls.Set{
				networkv1.NetworkAnnotationKey: defaultVPCNetwork,
			},
		},
		{
			desc: "multinic network",
			epLabels: k8slbls.Set{
				networkv1.NetworkAnnotationKey: "network-1",
			},
			want: true,
		},
	}
	for _, tc := range testcases {
		t.Run(tc.desc, func(t *testing.T) {
			got := skipEgressNATPolicy(tc.epLabels)
			if got != tc.want {
				t.Errorf("skipEgressNATPolicy() = %t, want %t", got, tc.want)
			}
		})
	}

}
