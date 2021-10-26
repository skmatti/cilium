//go:build !privileged_tests
// +build !privileged_tests

package controller

import (
	"fmt"
	"net"
	"strings"
	"testing"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/gke/apis/trafficsteering/v1alpha1"
	"github.com/cilium/cilium/pkg/maps/egressmap"
	"github.com/google/go-cmp/cmp"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

type key struct {
	sip string
	dst string
}

type fakeMap map[key]string

func keyOf(k *egressmap.Key4) key {
	// see getStaticPrefixBits in egressmap on how this is calculated.
	ones := k.PrefixLen - 32
	return key{
		sip: k.SourceIP.String(),
		dst: fmt.Sprintf("%s/%d", k.DestCIDR, ones),
	}
}

func (m fakeMap) Update(bk bpf.MapKey, value bpf.MapValue) error {
	egressKey, ok := bk.(*egressmap.Key4)
	if !ok {
		return fmt.Errorf("Update() called with bad key: %T", bk)
	}
	egressInfo4, ok := value.(*egressmap.EgressInfo4)
	if !ok {
		return fmt.Errorf("Update() called with bad value: %T", value)
	}

	k := keyOf(egressKey)

	if _, ok := m[k]; ok {
		return fmt.Errorf("Update() called with duplicated key: %#v", k)
	}
	m[k] = egressInfo4.TunnelEndpoint.String()
	return nil
}

func (m fakeMap) Delete(bk bpf.MapKey) error {
	egressKey, ok := bk.(*egressmap.Key4)
	if !ok {
		return fmt.Errorf("Delete() called with bad key: %T", bk)
	}
	k := keyOf(egressKey)
	if _, ok := m[k]; !ok {
		return fmt.Errorf("Delete() called with non-existent key: %#v", k)
	}
	delete(m, k)
	return nil
}

func buildTSObj(name, namespace string, dstCIDRs []string, nextHop string) *v1alpha1.TrafficSteering {
	return &v1alpha1.TrafficSteering{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Spec: v1alpha1.TrafficSteeringSpec{
			Selector: v1alpha1.TrafficSelector{
				DestinationCIDRs: dstCIDRs,
			},
			NextHopIP: nextHop,
		},
	}
}

func TestAddDelTSConfig(t *testing.T) {
	m := newManager()
	fm := fakeMap{}
	m.egressMap = fm
	m.podIPs = map[string]net.IP{
		"192.168.1.1": net.ParseIP("192.168.1.1"),
		"192.168.1.2": net.ParseIP("192.168.1.2"),
	}

	cfg1, err := parse(buildTSObj("ts-1", "default", []string{"10.1.1.0/24", "10.1.2.0/24"}, "10.1.1.1"))
	if err != nil {
		t.Fatal(err)
	}
	if err := m.addTSConfig(cfg1); err != nil {
		t.Fatalf("addTSConfig(%#v) failed: %v", cfg1, err)
	}
	// On duplicated call, it should return nil
	if err := m.addTSConfig(cfg1); err != nil {
		t.Fatalf("addTSConfig(%#v) failed: %v", cfg1, err)
	}
	want := map[key]string{}
	want[key{"192.168.1.1", "10.1.1.0/24"}] = "10.1.1.1"
	want[key{"192.168.1.2", "10.1.1.0/24"}] = "10.1.1.1"
	want[key{"192.168.1.1", "10.1.2.0/24"}] = "10.1.1.1"
	want[key{"192.168.1.2", "10.1.2.0/24"}] = "10.1.1.1"

	// config with duplicated cidr
	cfg2, err := parse(buildTSObj("ts-2", "default", []string{"10.1.1.0/24", "10.1.3.0/24"}, "10.1.1.1"))
	if err != nil {
		t.Fatal(err)
	}
	if err := m.addTSConfig(cfg2); err == nil {
		t.Fatalf("addTSConfig(%#v) should return error on duplicated cidr but returns nil", cfg1)
	}

	cfg3, err := parse(buildTSObj("ts-1", "default-2", []string{"10.1.3.0/24"}, "10.2.1.1"))
	if err != nil {
		t.Fatal(err)
	}
	if err := m.addTSConfig(cfg3); err != nil {
		t.Fatalf("addTSConfig(%#v) failed: %v", cfg1, err)
	}
	want[key{"192.168.1.1", "10.1.3.0/24"}] = "10.2.1.1"
	want[key{"192.168.1.2", "10.1.3.0/24"}] = "10.2.1.1"

	if diff := cmp.Diff(fm, fakeMap(want)); diff != "" {
		t.Fatalf("got different map (-got +want): %s", diff)
	}

	m.delTSConfig(cfg3.name)

	delete(want, key{"192.168.1.1", "10.1.3.0/24"})
	delete(want, key{"192.168.1.2", "10.1.3.0/24"})

	if diff := cmp.Diff(fm, fakeMap(want)); diff != "" {
		t.Fatalf("got different map after deletion (-got +want): %s", diff)
	}
}

func TestAddDelPodIP(t *testing.T) {
	m := newManager()
	fm := fakeMap{}
	m.egressMap = fm

	cfg1, err := parse(buildTSObj("ts-1", "default", []string{"10.1.1.0/24", "10.1.2.0/24"}, "10.1.1.1"))
	if err != nil {
		t.Fatal(err)
	}
	cfg2, err := parse(buildTSObj("ts-2", "default", []string{"10.1.3.0/24"}, "10.2.1.1"))
	if err != nil {
		t.Fatal(err)
	}
	m.tsConfigs[cfg1.name] = cfg1
	m.tsConfigs[cfg2.name] = cfg2

	want := map[key]string{}

	if err := m.addPodIP(net.ParseIP("192.168.1.1")); err != nil {
		t.Fatalf("m.addPodIP(192.168.1.1) returns error: %v", err)
	}
	want[key{"192.168.1.1", "10.1.1.0/24"}] = "10.1.1.1"
	want[key{"192.168.1.1", "10.1.2.0/24"}] = "10.1.1.1"
	want[key{"192.168.1.1", "10.1.3.0/24"}] = "10.2.1.1"

	// adding duplicate IP is no-op
	if err := m.addPodIP(net.ParseIP("192.168.1.1")); err != nil {
		t.Fatalf("calling m.addPodIP(192.168.1.1) second time returns error: %v", err)
	}

	if err := m.addPodIP(net.ParseIP("192.168.1.2")); err != nil {
		t.Fatalf("m.addPodIP(192.168.1.1) returns error: %v", err)
	}
	want[key{"192.168.1.2", "10.1.1.0/24"}] = "10.1.1.1"
	want[key{"192.168.1.2", "10.1.2.0/24"}] = "10.1.1.1"
	want[key{"192.168.1.2", "10.1.3.0/24"}] = "10.2.1.1"

	if diff := cmp.Diff(fm, fakeMap(want)); diff != "" {
		t.Fatalf("got different map (-got +want): %s", diff)
	}

	m.delPodIP(net.ParseIP("192.168.1.1"))
	delete(want, key{"192.168.1.1", "10.1.1.0/24"})
	delete(want, key{"192.168.1.1", "10.1.2.0/24"})
	delete(want, key{"192.168.1.1", "10.1.3.0/24"})

	if diff := cmp.Diff(fm, fakeMap(want)); diff != "" {
		t.Fatalf("got different map after deletion (-got +want): %s", diff)
	}
}

func TestParse(t *testing.T) {
	ip1 := net.ParseIP("192.168.0.1")
	_, ipNet1, _ := net.ParseCIDR("10.1.1.0/24")
	_, ipNet2, _ := net.ParseCIDR("10.1.2.0/24")
	tests := []struct {
		name        string
		dstCIDRs    []string
		nextHop     string
		want        *tsConfig
		errContains string
	}{
		{
			name:     "valid",
			dstCIDRs: []string{ipNet1.String()},
			nextHop:  ip1.String(),
			want: &tsConfig{
				dstCIDRs: map[string]*net.IPNet{
					ipNet1.String(): ipNet1,
				},
				nextHop: ip1,
			},
		},
		{
			name:     "valid two CIDRs",
			dstCIDRs: []string{ipNet1.String(), ipNet2.String()},
			nextHop:  ip1.String(),
			want: &tsConfig{
				dstCIDRs: map[string]*net.IPNet{
					ipNet1.String(): ipNet1,
					ipNet2.String(): ipNet2,
				},
				nextHop: ip1,
			},
		},
		{
			name:        "empty destination CIDR",
			dstCIDRs:    nil,
			nextHop:     ip1.String(),
			errContains: "DestinationCIDRs",
		},
		{
			name:        "invalid destination CIDR",
			dstCIDRs:    []string{"invalid-cidr"},
			nextHop:     ip1.String(),
			errContains: "invalid-cidr",
		},
		{
			name:        "non-ipv4 destination CIDR",
			dstCIDRs:    []string{"fc00::/64"},
			nextHop:     ip1.String(),
			errContains: "non-ipv4 address",
		},
		{
			name:        "duplicate destination CIDR",
			dstCIDRs:    []string{ipNet1.String(), ipNet1.String()},
			nextHop:     ip1.String(),
			errContains: "duplicated",
		},
		{
			name:        "empty nexthop",
			dstCIDRs:    []string{ipNet1.String()},
			nextHop:     "",
			errContains: "invalid nextHopIP",
		},
		{
			name:        "invalid nexthop",
			dstCIDRs:    []string{ipNet1.String()},
			nextHop:     "invalid-ip",
			errContains: "invalid-ip",
		},
		{
			name:        "non-ipv4 nexthop",
			dstCIDRs:    []string{ipNet1.String()},
			nextHop:     "fc00::",
			errContains: "non-ipv4",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			input := buildTSObj("ts", "namespace", tc.dstCIDRs, tc.nextHop)
			got, err := parse(input)
			if err != nil {
				if len(tc.errContains) > 0 {
					if !strings.Contains(err.Error(), tc.errContains) {
						t.Fatalf("parse(%#v) returns error %q but want it to contain %q", input, err, tc.errContains)
					}
					return
				}
				t.Fatalf("parse(%#v) returns error: %v", input, err)
			}
			if len(tc.errContains) > 0 {
				t.Fatalf("parse(%#v) returns nil but want error containing %q", input, tc.errContains)
			}
			tc.want.name = types.NamespacedName{
				Name:      "ts",
				Namespace: "namespace",
			}
			if diff := cmp.Diff(got, tc.want, cmp.AllowUnexported(tsConfig{})); diff != "" {
				t.Fatalf("parse(%#v) returns different result (-got + want): %s", input, diff)
			}
		})
	}
}
