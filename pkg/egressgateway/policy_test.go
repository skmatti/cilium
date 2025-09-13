// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package egressgateway

import (
	"net/netip"
	"testing"

	"github.com/cilium/cilium/pkg/gke/features"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestParseCEGP(t *testing.T) {
	// Enable annotation parsing for tests
	originalEnableGatewayIPFromAnnotation := features.GlobalConfig.EnableGatewayIPFromAnnotation
	features.GlobalConfig.EnableGatewayIPFromAnnotation = true
	defer func() {
		features.GlobalConfig.EnableGatewayIPFromAnnotation = originalEnableGatewayIPFromAnnotation
	}()

	nodeSelector1 := &slim_metav1.LabelSelector{
		MatchLabels: map[string]string{"node-role.kubernetes.io/control-plane": ""},
	}
	nodeSelector2 := &slim_metav1.LabelSelector{
		MatchLabels: map[string]string{"node-role.kubernetes.io/worker": ""},
	}

	dstCIDR := []v2.IPv4CIDR{"0.0.0.0/0"}

	tests := []struct {
		name           string
		cegp           *v2.CiliumEgressGatewayPolicy
		wantStaticIPs  []netip.Addr
		wantErr        bool
		wantErrString  string
		numPolicyConfs int
	}{
		{
			name: "no annotations",
			cegp: &v2.CiliumEgressGatewayPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "test-policy"},
				Spec: v2.CiliumEgressGatewayPolicySpec{
					EgressGateway: &v2.EgressGateway{
						NodeSelector: nodeSelector1,
					},
					DestinationCIDRs: dstCIDR,
				},
			},
			wantStaticIPs:  []netip.Addr{{}},
			wantErr:        false,
			numPolicyConfs: 1,
		},
		{
			name: "static gateway IP annotation",
			cegp: &v2.CiliumEgressGatewayPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-policy",
					Annotations: map[string]string{
						NetworkGatewayIPAnnotationKey: "192.168.1.100",
					},
				},
				Spec: v2.CiliumEgressGatewayPolicySpec{
					EgressGateway: &v2.EgressGateway{
						NodeSelector: nodeSelector1,
					},
					DestinationCIDRs: dstCIDR,
				},
			},
			wantStaticIPs:  []netip.Addr{netip.MustParseAddr("192.168.1.100")},
			wantErr:        false,
			numPolicyConfs: 1,
		},
		{
			name: "Cloud NAT gateway IP annotation with EgressGateways",
			cegp: &v2.CiliumEgressGatewayPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-policy",
					Annotations: map[string]string{
						CloudNATGatewaysAnnotationKey: `[{"egressIP":"1.2.3.4","gatewayIP":"10.0.0.1"}]`,
					},
				},
				Spec: v2.CiliumEgressGatewayPolicySpec{
					EgressGateways: []v2.EgressGateway{
						{
							NodeSelector: nodeSelector1,
							EgressIP:     "1.2.3.4",
						},
					},
					DestinationCIDRs: dstCIDR,
				},
			},
			wantStaticIPs:  []netip.Addr{netip.MustParseAddr("10.0.0.1")},
			wantErr:        false,
			numPolicyConfs: 1,
		},
		{
			name: "Cloud NAT gateway IP annotation with multiple EgressGateways",
			cegp: &v2.CiliumEgressGatewayPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-policy",
					Annotations: map[string]string{
						CloudNATGatewaysAnnotationKey: `[{"egressIP":"1.2.3.4","gatewayIP":"10.0.0.1"}, {"egressIP":"5.6.7.8","gatewayIP":"10.0.0.2"}]`,
					},
				},
				Spec: v2.CiliumEgressGatewayPolicySpec{
					EgressGateways: []v2.EgressGateway{
						{
							NodeSelector: nodeSelector1,
							EgressIP:     "1.2.3.4",
						},
						{
							NodeSelector: nodeSelector2,
							EgressIP:     "5.6.7.8",
						},
					},
					DestinationCIDRs: dstCIDR,
				},
			},
			wantStaticIPs:  []netip.Addr{netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("10.0.0.2")},
			wantErr:        false,
			numPolicyConfs: 2,
		},
		{
			name: "Cloud NAT gateway IP annotation with EgressGateways, egress IP not in annotation",
			cegp: &v2.CiliumEgressGatewayPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-policy",
					Annotations: map[string]string{
						CloudNATGatewaysAnnotationKey: `[{"egressIP":"1.2.3.4","gatewayIP":"10.0.0.1"}]`,
					},
				},
				Spec: v2.CiliumEgressGatewayPolicySpec{
					EgressGateways: []v2.EgressGateway{
						{
							NodeSelector: nodeSelector1,
							EgressIP:     "5.6.7.8", // This IP is not in the annotation
						},
					},
					DestinationCIDRs: dstCIDR,
				},
			},
			wantErr:       true,
			wantErrString: "annotation cloud-nat-gateways doesn't include egress IP 5.6.7.8",
		},
		{
			name: "Both annotations with EgressGateway (single gateway)",
			cegp: &v2.CiliumEgressGatewayPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-policy",
					Annotations: map[string]string{
						NetworkGatewayIPAnnotationKey: "192.168.1.100",
						CloudNATGatewaysAnnotationKey: `[{"egressIP":"1.2.3.4","gatewayIP":"10.0.0.1"}]`,
					},
				},
				Spec: v2.CiliumEgressGatewayPolicySpec{
					EgressGateway: &v2.EgressGateway{
						NodeSelector: nodeSelector1,
						EgressIP:     "1.2.3.5",
					},
					DestinationCIDRs: dstCIDR,
				},
			},
			wantStaticIPs:  []netip.Addr{netip.MustParseAddr("192.168.1.100")},
			wantErr:        false,
			numPolicyConfs: 1,
		},
		{
			name: "Both annotations with EgressGateways (multigateway)",
			cegp: &v2.CiliumEgressGatewayPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-policy",
					Annotations: map[string]string{
						NetworkGatewayIPAnnotationKey: "192.168.1.100",
						CloudNATGatewaysAnnotationKey: `[{"egressIP":"1.2.3.4","gatewayIP":"10.0.0.1"}]`,
					},
				},
				Spec: v2.CiliumEgressGatewayPolicySpec{
					EgressGateways: []v2.EgressGateway{
						{
							NodeSelector: nodeSelector1,
							EgressIP:     "1.2.3.4",
						},
					},
					DestinationCIDRs: dstCIDR,
				},
			},
			wantStaticIPs:  []netip.Addr{netip.MustParseAddr("10.0.0.1")},
			wantErr:        false,
			numPolicyConfs: 1,
		},
		{
			name: "Malformed Cloud NAT annotation",
			cegp: &v2.CiliumEgressGatewayPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-policy",
					Annotations: map[string]string{
						CloudNATGatewaysAnnotationKey: `[{"egressIP":"1.2.3.4","gatewayIP":"10.0.0.1"`,
					},
				},
				Spec: v2.CiliumEgressGatewayPolicySpec{
					EgressGateway: &v2.EgressGateway{
						NodeSelector: nodeSelector1,
					},
					DestinationCIDRs: dstCIDR,
				},
			},
			wantErr:       true,
			wantErrString: "error getting Cloud NAT gateway IPs in CiliumEgressGatewayPolicy",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policyConfig, err := ParseCEGP(tt.cegp)

			if tt.wantErr {
				require.Error(t, err)
				if tt.wantErrString != "" {
					require.Contains(t, err.Error(), tt.wantErrString)
				}
			} else {
				require.NoError(t, err)
				require.NotNil(t, policyConfig)
				require.Len(t, policyConfig.policyGwConfigs, tt.numPolicyConfs)
				for i, wantStaticIP := range tt.wantStaticIPs {
					if wantStaticIP.IsValid() {
						require.True(t, wantStaticIP == policyConfig.policyGwConfigs[i].staticGatewayIP)
					} else {
						require.False(t, policyConfig.policyGwConfigs[i].staticGatewayIP.IsValid())
					}
				}
			}
		})
	}
}
