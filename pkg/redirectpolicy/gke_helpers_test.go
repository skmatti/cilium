// +build !privileged_tests

package redirectpolicy

import (
	"testing"

	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/policy/api"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

// apiVersion: "cilium.io/v2"
// kind: CiliumLocalRedirectPolicy
// metadata:
//  name: "default"
//  namespace: kube-system
//spec:
//  redirectFrontend:
//    serviceMatcher:
//      serviceName: kube-dns
//      namespace: kube-system
//      toPorts:
//        - name: dns
//          port: "53"
//          protocol: UDP
//        - name: dns-tcp
//          port: "53"
//          protocol: TCP
//  redirectBackend:
//    localEndpointSelector:
//      matchLabels:
//        k8s-app: node-local-dns
//    toPorts:
//      - name: dns
//        port: "53"
//        protocol: UDP
//      - name: dns-tcp
//        port: "53"
//        protocol: TCP

var (
	nodelocaldns_clrp = v2.CiliumLocalRedirectPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "default",
			Namespace: "kube-system",
		},
		Spec: v2.CiliumLocalRedirectPolicySpec{
			RedirectFrontend: v2.RedirectFrontend{
				ServiceMatcher: &v2.ServiceInfo{
					Name:      "kube-dns",
					Namespace: "kube-system",
					ToPorts: []v2.PortInfo{
						{
							Port:     "53",
							Protocol: api.ProtoUDP,
							Name:     "dns",
						},
						{
							Port:     "53",
							Protocol: api.ProtoTCP,
							Name:     "dns-tcp",
						},
					},
				},
			},
			RedirectBackend: v2.RedirectBackend{
				LocalEndpointSelector: slim_metav1.LabelSelector{
					MatchLabels: map[string]string{
						"k8s-app": "node-local-dns",
					},
				},
				ToPorts: []v2.PortInfo{
					{
						Port:     "53",
						Protocol: api.ProtoUDP,
						Name:     "dns",
					},
					{
						Port:     "53",
						Protocol: api.ProtoTCP,
						Name:     "dns-tcp",
					},
				},
			},
		},
	}
)

func TestLRPContruction(t *testing.T) {
	for _, tc := range []struct {
		desc        string
		clrpConfig  *v2.CiliumLocalRedirectPolicy
		constructor func(string, string, types.UID) *LRPConfig
		expectEqual bool
	}{
		{
			desc:        "valid nodelocaldns config",
			clrpConfig:  &nodelocaldns_clrp,
			constructor: ConstructNodeLocalDNSLRP,
		},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			parsed, err := Parse(tc.clrpConfig, true)
			if err != nil {
				t.Fatalf("cannot parse LRP spec %v", tc.clrpConfig)
			}
			constructed := tc.constructor(parsed.id.Name, parsed.id.Namespace, parsed.uid)
			equals := parsed == constructed
			if equals != tc.expectEqual {
				t.Fatalf("got %v, want %v", equals, tc.expectEqual)
			}
		})
	}
}
