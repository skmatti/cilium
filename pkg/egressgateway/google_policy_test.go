package egressgateway

import (
	"testing"

	networkv1 "github.com/GoogleCloudPlatform/gke-networking-api/apis/network/v1"
	"github.com/cilium/cilium/pkg/gke/features"
	k8slbls "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/labels"
)

func TestSkipEgressNATPolicy(t *testing.T) {
	testcases := []struct {
		desc                          string
		enableGoogleMultiNICEgressNAT bool
		epLabels                      k8slbls.Labels
		want                          bool
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
				networkv1.NetworkAnnotationKey: "default-vpc",
			},
			want: true,
		},
		{
			desc: "multinic network",
			epLabels: k8slbls.Set{
				networkv1.NetworkAnnotationKey: "network-1",
			},
			want: true,
		},
		{
			desc:                          "default-vpc network with flag enabled",
			enableGoogleMultiNICEgressNAT: true,
			epLabels: k8slbls.Set{
				networkv1.NetworkAnnotationKey: "default-vpc",
			},
		},
	}
	for _, tc := range testcases {
		t.Run(tc.desc, func(t *testing.T) {
			if tc.enableGoogleMultiNICEgressNAT {
				currValue := features.GlobalConfig.EnableGoogleMultiNICEgressNAT
				defer func() {
					features.GlobalConfig.EnableGoogleMultiNICEgressNAT = currValue
				}()
				features.GlobalConfig.EnableGoogleMultiNICEgressNAT = true
			}
			got := skipEgressNATPolicy(tc.epLabels)
			if got != tc.want {
				t.Errorf("skipEgressNATPolicy() = %t, want %t", got, tc.want)
			}
		})
	}

}
