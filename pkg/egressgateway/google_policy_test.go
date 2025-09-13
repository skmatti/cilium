package egressgateway

import (
	"net/netip"
	"reflect"
	"testing"

	networkv1 "github.com/GoogleCloudPlatform/gke-networking-api/apis/network/v1"
	"github.com/cilium/cilium/pkg/gke/features"
	k8slbls "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/labels"
	"github.com/cilium/cilium/pkg/maps/egressmap"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
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

func Test_PolicyConfig_regenerateGatewayConfig(t *testing.T) {
	k := setupEgressGatewayTestSuite(t)

	type fields struct {
		policyGwConfigs []policyGatewayConfig
	}
	tests := []struct {
		name   string
		fields fields
		want   []gatewayConfig
	}{
		{
			name: "single_static_gateway_IP",
			fields: fields{
				policyGwConfigs: []policyGatewayConfig{
					{
						staticGatewayIP: netip.MustParseAddr("192.0.2.1"),
					},
				},
			},
			want: []gatewayConfig{
				{
					gatewayIP:                    netip.MustParseAddr("192.0.2.1"),
					localNodeConfiguredAsGateway: false,
				},
			},
		},
		{
			name: "multiple_static_gateway_IPs",
			fields: fields{
				policyGwConfigs: []policyGatewayConfig{
					{
						staticGatewayIP: netip.MustParseAddr("192.0.2.1"),
					},
					{
						staticGatewayIP: netip.MustParseAddr("192.0.2.2"),
					},
				},
			},
			want: []gatewayConfig{
				{
					gatewayIP:                    netip.MustParseAddr("192.0.2.1"),
					localNodeConfiguredAsGateway: false,
				},
				{
					gatewayIP:                    netip.MustParseAddr("192.0.2.2"),
					localNodeConfiguredAsGateway: false,
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &PolicyConfig{
				policyGwConfigs: tt.fields.policyGwConfigs,
			}
			config.regenerateGatewayConfig(k.manager)
			got := config.gatewayConfigs
			opts := []cmp.Option{
				cmpopts.IgnoreFields(gatewayConfig{}, "ifaceName", "egressIP"),
				cmp.Exporter(func(t reflect.Type) bool {
					return t == reflect.TypeOf(gatewayConfig{})
				}),
				cmp.Comparer(func(x, y netip.Addr) bool { return x == y }),
			}
			if diff := cmp.Diff(tt.want, got, opts...); diff != "" {
				t.Errorf("PolicyConfig.regenerateGatewayConfig() mismatch (-want +got):\n%s", diff)
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

func TestCloudNATGatewayEncoding(t *testing.T) {
	t.Run("encodeCloudNATGatewayInfos", func(t *testing.T) {
		tests := []struct {
			name    string
			gws     []CloudNATGatewayIPs
			want    string
			wantErr bool
		}{
			{
				name: "single gateway",
				gws: []CloudNATGatewayIPs{
					{EgressIP: netip.MustParseAddr("1.2.3.4"), GatewayIP: netip.MustParseAddr("10.0.0.1")},
				},
				want: `[{"egressIP":"1.2.3.4","gatewayIP":"10.0.0.1"}]`,
			},
			{
				name: "multiple gateways",
				gws: []CloudNATGatewayIPs{
					{EgressIP: netip.MustParseAddr("1.2.3.4"), GatewayIP: netip.MustParseAddr("10.0.0.1")},
					{EgressIP: netip.MustParseAddr("5.6.7.8"), GatewayIP: netip.MustParseAddr("10.0.0.2")},
				},
				want: `[{"egressIP":"1.2.3.4","gatewayIP":"10.0.0.1"},{"egressIP":"5.6.7.8","gatewayIP":"10.0.0.2"}]`,
			},
			{
				name: "empty gateways",
				gws:  []CloudNATGatewayIPs{},
				want: `[]`,
			},
			{
				name: "nil gateways",
				gws:  nil,
				want: `null`,
			},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				got, err := EncodeCloudNATGatewayInfos(tt.gws)
				if (err != nil) != tt.wantErr {
					t.Errorf("encodeCloudNATGatewayInfos() error = %v, wantErr %v", err, tt.wantErr)
					return
				}
				if got != tt.want {
					t.Errorf("encodeCloudNATGatewayInfos() = %v, want %v", got, tt.want)
				}
			})
		}
	})

	t.Run("decodeCloudNATGateways", func(t *testing.T) {
		tests := []struct {
			name       string
			jsonString string
			want       []CloudNATGatewayIPs
			wantErr    bool
		}{
			{
				name:       "single gateway",
				jsonString: `[{"egressIP":"1.2.3.4","gatewayIP":"10.0.0.1"}]`,
				want: []CloudNATGatewayIPs{
					{EgressIP: netip.MustParseAddr("1.2.3.4"), GatewayIP: netip.MustParseAddr("10.0.0.1")},
				},
			},
			{
				name:       "multiple gateways",
				jsonString: `[{"egressIP":"1.2.3.4","gatewayIP":"10.0.0.1"},{"egressIP":"5.6.7.8","gatewayIP":"10.0.0.2"}]`,
				want: []CloudNATGatewayIPs{
					{EgressIP: netip.MustParseAddr("1.2.3.4"), GatewayIP: netip.MustParseAddr("10.0.0.1")},
					{EgressIP: netip.MustParseAddr("5.6.7.8"), GatewayIP: netip.MustParseAddr("10.0.0.2")},
				},
			},
			{
				name:       "empty gateways",
				jsonString: `[]`,
				want:       []CloudNATGatewayIPs{},
			},
			{
				name:       "null gateways",
				jsonString: `null`,
				want:       nil,
			},
			{
				name:       "malformed json",
				jsonString: `[{"egressIP":"1.2.3.4"`,
				wantErr:    true,
			},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				got, err := DecodeCloudNATGateways(tt.jsonString)
				if (err != nil) != tt.wantErr {
					t.Errorf("decodeCloudNATGateways() error = %v, wantErr %v", err, tt.wantErr)
					return
				}
				if !reflect.DeepEqual(got, tt.want) {
					t.Errorf("decodeCloudNATGateways() = %v, want %v", got, tt.want)
				}
			})
		}
	})

	t.Run("getCloudNATGatewayIPs", func(t *testing.T) {
		tests := []struct {
			name        string
			annotations map[string]string
			want        []CloudNATGatewayIPs
			wantErr     bool
		}{
			{
				name: "valid annotation",
				annotations: map[string]string{
					CloudNATGatewaysAnnotationKey: `[{"egressIP":"1.2.3.4","gatewayIP":"10.0.0.1"}]`,
				},
				want: []CloudNATGatewayIPs{
					{EgressIP: netip.MustParseAddr("1.2.3.4"), GatewayIP: netip.MustParseAddr("10.0.0.1")},
				},
			},
			{
				name:        "nil annotations",
				annotations: nil,
				want:        nil,
			},
			{
				name:        "empty annotations",
				annotations: map[string]string{},
				want:        nil,
			},
			{
				name: "annotation key present but empty value",
				annotations: map[string]string{
					CloudNATGatewaysAnnotationKey: "",
				},
				want: nil,
			},
			{
				name: "malformed json in annotation",
				annotations: map[string]string{
					CloudNATGatewaysAnnotationKey: `[{"egressIP":"1.2.3.4"`,
				},
				wantErr: true,
			},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				got, err := getCloudNATGatewayIPs(tt.annotations)
				if (err != nil) != tt.wantErr {
					t.Errorf("getCloudNATGatewayIPs() error = %v, wantErr %v", err, tt.wantErr)
					return
				}
				if !reflect.DeepEqual(got, tt.want) {
					t.Errorf("getCloudNATGatewayIPs() = %v, want %v", got, tt.want)
				}
			})
		}
	})
}
