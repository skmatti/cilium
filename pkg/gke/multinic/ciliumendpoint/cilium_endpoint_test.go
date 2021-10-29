//go:build !privileged_tests
// +build !privileged_tests

package ciliumendpoint

import (
	"testing"

	"github.com/cilium/cilium/pkg/endpoint"
	multinicep "github.com/cilium/cilium/pkg/gke/multinic/endpoint"
	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/k8s/types"
	"github.com/cilium/cilium/pkg/option"
	"github.com/google/go-cmp/cmp"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestUpdateMultiNICCEP(t *testing.T) {
	testcases := []struct {
		desc         string
		isVETH       bool
		cep, wantCEP *cilium_v2.CiliumEndpoint
	}{
		{
			desc:    "veth endpoint",
			isVETH:  true,
			cep:     &cilium_v2.CiliumEndpoint{},
			wantCEP: &cilium_v2.CiliumEndpoint{},
		},
		{
			desc: "without annotation",
			cep:  &cilium_v2.CiliumEndpoint{},
			wantCEP: &cilium_v2.CiliumEndpoint{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{cepAnnotationKey: enabledMultiNIC},
				},
			},
		},
		{
			desc: "with annotation",
			cep: &cilium_v2.CiliumEndpoint{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{"foo-annotation": "foo"},
				},
			},
			wantCEP: &cilium_v2.CiliumEndpoint{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						"foo-annotation": "foo",
						cepAnnotationKey: enabledMultiNIC,
					},
				},
			},
		},
	}
	for _, tc := range testcases {
		t.Run(tc.desc, func(t *testing.T) {
			e := &endpoint.Endpoint{}
			e.UpdateLogger(nil)
			if !tc.isVETH {
				e.SetDeviceTypeForTest(multinicep.EndpointDeviceMACVTAP)
				option.Config.EnableGoogleMultiNIC = true
				defer func() {
					option.Config.EnableGoogleMultiNIC = false
				}()
			}
			AddAnnotationIfMultiNIC(e, tc.cep)
			if s := cmp.Diff(tc.cep, tc.wantCEP); s != "" {
				t.Fatalf("UpdateMultiNICCEP() returns unexpected output (-got, +want):\n%s", s)
			}
		})
	}
}

func TestIsMultiNICCEP(t *testing.T) {
	testcases := []struct {
		desc  string
		cep   *cilium_v2.CiliumEndpoint
		cepv1 *types.CiliumEndpoint
		want  bool
	}{
		{
			desc: "v2 cep without annotation",
			cep:  &cilium_v2.CiliumEndpoint{},
			want: false,
		},
		{
			desc: "v2 cep with annotation",
			cep: &cilium_v2.CiliumEndpoint{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{cepAnnotationKey: enabledMultiNIC},
				},
			},
			want: true,
		},
		{
			desc:  "v1 cep without annotation",
			cepv1: &types.CiliumEndpoint{},
			want:  false,
		},
		{
			desc: "v1 cep with annotation",
			cepv1: &types.CiliumEndpoint{
				ObjectMeta: slim_metav1.ObjectMeta{
					Annotations: map[string]string{cepAnnotationKey: enabledMultiNIC},
				},
			},
			want: true,
		},
	}
	for _, tc := range testcases {
		t.Run(tc.desc, func(t *testing.T) {
			var got bool
			if tc.cep != nil {
				got = IsMultiNICCEP(tc.cep)
			} else if tc.cepv1 != nil {
				got = IsMultiNICCEP(tc.cepv1)
			}
			if got != tc.want {
				t.Fatalf("IsMultiNICCEP return %t but want %t", got, tc.want)
			}
		})
	}
}

func TestGetPodNameFromCEP(t *testing.T) {
	testcases := []struct {
		desc    string
		cepv1   *types.CiliumEndpoint
		want    string
		wantErr string
	}{
		{
			desc: "pod OwnerReferences exists",
			cepv1: &types.CiliumEndpoint{
				ObjectMeta: slim_metav1.ObjectMeta{
					Name: "foo",
					OwnerReferences: []slim_metav1.OwnerReference{
						{
							Kind: "Pod",
							Name: "bar",
						},
					},
					Annotations: map[string]string{cepAnnotationKey: enabledMultiNIC},
				},
			},
			want: "bar",
		},
		{
			desc: "no pod OwnerReferences",
			cepv1: &types.CiliumEndpoint{
				ObjectMeta: slim_metav1.ObjectMeta{
					Name:        "foo",
					Annotations: map[string]string{cepAnnotationKey: enabledMultiNIC},
				},
			},
			wantErr: "pod name not found in OwnerReferences for multiNIC CEP \"foo\"",
		},
		{
			desc: "no multiNIC annotation",
			cepv1: &types.CiliumEndpoint{
				ObjectMeta: slim_metav1.ObjectMeta{
					Name: "foo",
				},
			},
			want: "foo",
		},
	}
	for _, tc := range testcases {
		t.Run(tc.desc, func(t *testing.T) {
			got, gotErr := GetPodNameFromCEP(tc.cepv1)
			if gotErr != nil {
				if tc.wantErr == "" {
					t.Fatalf("GetPodNameFromCEP return error %s but want nil", gotErr)
				}
				if gotErr.Error() != tc.wantErr {
					t.Fatalf("GetPodNameFromCEP return error %s but want %s", gotErr, tc.wantErr)
				}
			}
			if got != tc.want {
				t.Fatalf("GetPodNameFromCEP return %s but want %s", got, tc.want)
			}
		})
	}
}
