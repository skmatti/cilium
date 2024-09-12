package k8s

import (
	"strings"
	"testing"

	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	cilium_v2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/k8s/types"
	"github.com/google/go-cmp/cmp"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestCEPKey(t *testing.T) {
	tests := []struct {
		name string
		ccep cilium_v2.NetworkingEndpoint
		ns   string
		want resource.Key
	}{
		{
			name: "nil",
		},
		{
			name: "empty",
			ccep: &cilium_v2alpha1.CoreCiliumEndpoint{},
		},
		{
			name: "cluster_scoped",
			ccep: &cilium_v2alpha1.CoreCiliumEndpoint{
				Name: "cep",
			},
			want: resource.Key{Name: "cep"},
		},
		{
			name: "namespaced",
			ccep: &cilium_v2alpha1.CoreCiliumEndpoint{
				Name: "cep",
			},
			ns:   "kube-system",
			want: resource.Key{Name: "cep", Namespace: "kube-system"},
		},
		{
			name: "nil_addressing",
			ccep: &cilium_v2alpha1.CoreCiliumEndpoint{
				Name:       "cep",
				Networking: &v2.EndpointNetworking{},
			},
			want: resource.Key{Name: "cep"},
		},
		{
			name: "empty_addressing",
			ccep: &cilium_v2alpha1.CoreCiliumEndpoint{
				Name: "cep",
				Networking: &v2.EndpointNetworking{
					Addressing: v2.AddressPairList{},
				},
			},
			want: resource.Key{Name: "cep"},
		},
		{
			name: "ipv4",
			ccep: &cilium_v2alpha1.CoreCiliumEndpoint{
				Name: "cep",
				Networking: &v2.EndpointNetworking{
					Addressing: v2.AddressPairList{
						{IPV4: "1.1.1.1"},
					},
				},
			},
			want: resource.Key{Name: "cep1-1-1-1"},
		},
		{
			name: "ipv6",
			ccep: &cilium_v2alpha1.CoreCiliumEndpoint{
				Name: "cep",
				Networking: &v2.EndpointNetworking{
					Addressing: v2.AddressPairList{
						{IPV6: "1::1"},
					},
				},
			},
			want: resource.Key{Name: "cep1--1"},
		},
		{
			name: "prefer_ipv4",
			ccep: &cilium_v2alpha1.CoreCiliumEndpoint{
				Name: "cep",
				Networking: &v2.EndpointNetworking{
					Addressing: v2.AddressPairList{
						{
							IPV4: "1.1.1.1",
							IPV6: "1::1",
						},
					},
				},
			},
			want: resource.Key{Name: "cep1-1-1-1"},
		},
		{
			name: "truncate_cep",
			ccep: &cilium_v2alpha1.CoreCiliumEndpoint{
				Name: strings.Repeat("t", 253),
				Networking: &v2.EndpointNetworking{
					Addressing: v2.AddressPairList{
						{IPV4: "1.1.1.1"},
					},
				},
			},
			want: resource.Key{Name: strings.Repeat("t", 246) + "1-1-1-1"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := CEPKey(tc.ccep, tc.ns); got != tc.want {
				t.Errorf("CEPKey(...) = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestCEPIndexFunc(t *testing.T) {
	testsCases := []struct {
		name string
		obj  any
		want []string
	}{
		{
			name: "empty",
			obj:  &v2.CiliumEndpoint{},
			want: []string{""},
		},
		{
			name: "name",
			obj: &v2.CiliumEndpoint{
				ObjectMeta: metav1.ObjectMeta{Name: "cep"},
			},
			want: []string{"cep"},
		},
		{
			name: "namespaced",
			obj: &v2.CiliumEndpoint{
				ObjectMeta: metav1.ObjectMeta{Name: "cep", Namespace: "ns"},
			},
			want: []string{"ns/cep"},
		},
	}
	for _, tc := range testsCases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := CEPIndexFunc(tc.obj)
			if err != nil {
				t.Fatalf("Unexpected error from CEPIndexFunc(...); got: %v", err)
			}
			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Fatalf("Unexpected CEPIndexFunc() diff (-want +got):\n%s", diff)
			}
		})
	}
}

func TestCEPIndexFunc_Errors(t *testing.T) {
	testsCases := []struct {
		name string
		obj  any
	}{
		{
			name: "nil",
		},
		{
			name: "unsupported",
			obj:  &types.CiliumEndpoint{},
		},
	}
	for _, tc := range testsCases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := CEPIndexFunc(tc.obj)
			if err == nil {
				t.Fatalf("Expected error from CEPIndexFunc(...); got %v", got)
			}
		})
	}
}

func Test_truncate(t *testing.T) {
	type args struct {
	}
	testCases := []struct {
		name   string
		input  string
		length int
		want   string
	}{
		{
			name: "empty",
		},
		{
			name:  "zero_len",
			input: "foo",
		},
		{
			name:  "zero_len",
			input: "foo",
		},
		{
			name:   "truncate_bar",
			input:  "foobar",
			length: len("foo"),
			want:   "foo",
		},
		{
			name:   "truncate_baz",
			input:  "foobarbaz",
			length: len("foobar"),
			want:   "foobar",
		},
		{
			name:   "length_exceeds",
			input:  "foo",
			length: len("foo") + 1,
			want:   "foo",
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if got := truncate(tc.input, tc.length); got != tc.want {
				t.Errorf("truncate() = %v, want %v", got, tc.want)
			}
		})
	}
}
