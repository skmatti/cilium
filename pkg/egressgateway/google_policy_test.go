package egressgateway

import (
	"reflect"
	"testing"

	networkv1 "github.com/GoogleCloudPlatform/gke-networking-api/apis/network/v1"
	"github.com/cilium/cilium/pkg/gke/features"
	k8slbls "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/labels"
	"github.com/cilium/cilium/pkg/maps/egressmap"
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

func TestParseConnectionTimeouts(t *testing.T) {
	testcases := []struct {
		desc        string
		annotations map[string]string
		want        *egressmap.ConnectionTimeouts
		wantErr     bool
	}{
		{
			desc:        "empty annotations",
			annotations: map[string]string{},
			want:        nil,
			wantErr:     false,
		},
		{
			desc: "valid annotations",
			annotations: map[string]string{
				TimeoutRegularAnyKey:    "100",
				TimeoutRegularTcpKey:    "200",
				TimeoutRegularTcpSynKey: "300",
				TimeoutRegularTcpFinKey: "400",
			},
			want: &egressmap.ConnectionTimeouts{
				BpfCtTimeoutRegularAny:    100,
				BpfCtTimeoutRegularTcp:    200,
				BpfCtTimeoutRegularTcpSyn: 300,
				BpfCtTimeoutRegularTcpFin: 400,
			},
			wantErr: false,
		},
		{
			desc: "valid annotations",
			annotations: map[string]string{
				TimeoutRegularAnyKey:    "100",
				TimeoutRegularTcpKey:    "200",
				TimeoutRegularTcpSynKey: "300",
				TimeoutRegularTcpFinKey: "400",
			},
			want: &egressmap.ConnectionTimeouts{
				BpfCtTimeoutRegularAny:    100,
				BpfCtTimeoutRegularTcp:    200,
				BpfCtTimeoutRegularTcpSyn: 300,
				BpfCtTimeoutRegularTcpFin: 400,
			},
			wantErr: false,
		},
		{
			desc: "partial timeouts values",
			annotations: map[string]string{
				TimeoutRegularAnyKey: "abc",
			},
			want:    nil,
			wantErr: true,
		},
		{
			desc: "invalid timeouts value",
			annotations: map[string]string{
				TimeoutRegularAnyKey:    "a",
				TimeoutRegularTcpFinKey: "b",
			},
			want:    &egressmap.ConnectionTimeouts{},
			wantErr: true,
		},
		{
			desc: "zero timeouts value",
			annotations: map[string]string{
				TimeoutRegularAnyKey:    "0",
				TimeoutRegularTcpFinKey: "0",
			},
			want:    &egressmap.ConnectionTimeouts{},
			wantErr: true,
		},
	}
	for _, tc := range testcases {
		t.Run(tc.desc, func(t *testing.T) {
			connectionTimeouts, err := parseConnectionTimeouts(tc.annotations)

			if err != nil && tc.wantErr {
				return
			}

			if err == nil && tc.wantErr {
				t.Fatal("Got unexpected err: %w", err)
			}

			if !reflect.DeepEqual(tc.want, connectionTimeouts) {
				t.Fatalf("Timeout mismatch:\nwant: %+v\ngot:  %+v", tc.want, connectionTimeouts)
			}
		})
	}
}
