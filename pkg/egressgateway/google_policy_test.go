package egressgateway

import (
	"net/netip"
	"reflect"
	"testing"

	networkv1 "github.com/GoogleCloudPlatform/gke-networking-api/apis/network/v1"
	"github.com/cilium/cilium/pkg/gke/features"
	k8slbls "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/labels"
	"github.com/cilium/cilium/pkg/maps/egressmap"
	"github.com/onsi/gomega/format"
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

func TestStaticGatewayIP(t *testing.T) {
	tests := []struct {
		name        string
		annotations map[string]string
		gatewayIP   netip.Addr
	}{
		{
			name:        "nil_annotations",
			annotations: nil,
			gatewayIP:   netip.Addr{},
		},
		{
			name:        "empty_annotations",
			annotations: map[string]string{},
			gatewayIP:   netip.Addr{},
		},
		{
			name: "gateway_IP",
			annotations: map[string]string{
				NetworkGatewayIPAnnotationKey: "1.1.1.1",
			},
			gatewayIP: netip.MustParseAddr("1.1.1.1"),
		},
		{
			name: "empty_gateway_IP",
			annotations: map[string]string{
				NetworkGatewayIPAnnotationKey: "",
			},
			gatewayIP: netip.Addr{},
		},
		{
			name: "malformed_gateway_IP",
			annotations: map[string]string{
				NetworkGatewayIPAnnotationKey: "1.1.1.1.1",
			},
			gatewayIP: netip.Addr{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := staticGatewayIP(tt.annotations)
			if got != tt.gatewayIP {
				t.Errorf("got %v, want %v\n", got, tt.gatewayIP)
			}
		})
	}
}

func Test_PolicyConfig_regenerateGatewayConfig(t *testing.T) {
	type fields struct {
		policyGwConfig *policyGatewayConfig
	}
	tests := []struct {
		name   string
		fields fields
		want   gatewayConfig
	}{
		{
			name: "static_gateway_IP",
			fields: fields{
				policyGwConfig: &policyGatewayConfig{
					staticGatewayIP: netip.MustParseAddr(egressIP1),
				},
			},
			want: gatewayConfig{
				gatewayIP:                    netip.MustParseAddr(egressIP1),
				localNodeConfiguredAsGateway: false,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := Params{
				IdentityAllocator: identityAllocator,
				// DaemonConfig: &option.DaemonConfig{
				// 	EnableIPv4EgressGateway: true,
				// },
			}
			manager := &Manager{
				policyConfigs:           make(map[policyID]*PolicyConfig),
				policyConfigsBySourceIP: make(map[string][]*PolicyConfig),
				epDataStore:             make(map[endpointID]*endpointMetadata),
				identityAllocator:       p.IdentityAllocator,
				googleManager:           NewGoogleManager(p.FeaturesConfig.EgressGatewayPendingIdentityExpirySeconds),
			}

			config := &PolicyConfig{
				policyGwConfig: tt.fields.policyGwConfig,
			}
			config.regenerateGatewayConfig(manager)
			got := config.gatewayConfig

			if got.gatewayIP.String() != tt.want.gatewayIP.String() ||
				got.localNodeConfiguredAsGateway != tt.want.localNodeConfiguredAsGateway {
				t.Errorf("PolicyConfig.regenerateGatewayConfig() = %v, want %v", format.Object(got, 0), format.Object(tt.want, 0))
			}
		})
	}
}
