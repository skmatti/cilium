//go:build !privileged_tests
// +build !privileged_tests

package endpoint

import (
	"testing"

	multinicep "github.com/cilium/cilium/pkg/gke/multinic/endpoint"
	"github.com/cilium/cilium/pkg/option"
)

const (
	podName     = "fooPod"
	ifNameInPod = "fooEth0"
	// podNameWithMaxLength has 236 character length which should generate
	// the cep name with maximum length (253) when using ifNameInPod above
	// and no need to truncate.
	podNameWithMaxLength = "FWVQZcvBFvHEVVmdhCeAaCpDnWftvyqMasxPHOsuswqGTgIoTqddHnASNVdfsjiHkdmkxOvDziEwXShFFWUVcHCuAJiHZKjXCDCeKkAnMWaSAefKPjInundJPkurZxRXaWAQOejvCrRmlZAgIYIcWWLncKsnxYGDurlAyQZGKVFjctaenmZeTVVvCZxASFGgOnnSAABkujSXaRajzGjssGCrgKWxlZQYVjeLEZezscql"
)

func TestGenerateCEPName(t *testing.T) {
	testcases := []struct {
		desc       string
		endpoint   *Endpoint
		want       string
		wantLength int
	}{
		{
			desc: "veth endpoint",
			endpoint: &Endpoint{
				K8sPodName: podName,
			},
			want:       podName,
			wantLength: 6,
		},
		{
			desc: "multinic endpoint",
			endpoint: &Endpoint{
				K8sPodName:  podName,
				ifNameInPod: ifNameInPod,
				deviceType:  multinicep.EndpointDeviceMACVTAP,
			},
			want:       "fooPod-fooEth0-d34eb6b4",
			wantLength: 23,
		},
		{
			desc: "multinic endpoint with maximum length pod name",
			endpoint: &Endpoint{
				K8sPodName:  podNameWithMaxLength,
				ifNameInPod: ifNameInPod,
				deviceType:  multinicep.EndpointDeviceMACVTAP,
			},
			want:       podNameWithMaxLength + "-fooEth0-f73e6eb0",
			wantLength: 253,
		},
		{
			desc: "multinic endpoint need truncate",
			endpoint: &Endpoint{
				K8sPodName:  podNameWithMaxLength + "0",
				ifNameInPod: ifNameInPod,
				deviceType:  multinicep.EndpointDeviceMACVTAP,
			},
			want:       podNameWithMaxLength + "-fooEth0-3f4d52c3",
			wantLength: 253,
		},
	}
	for _, tc := range testcases {
		t.Run(tc.desc, func(t *testing.T) {
			if tc.endpoint.GetDeviceType() != multinicep.EndpointDeviceVETH {
				option.Config.EnableGoogleMultiNIC = true
				defer func() {
					option.Config.EnableGoogleMultiNIC = false
				}()
			}
			got := tc.endpoint.GenerateCEPName()
			if len(got) != tc.wantLength {
				t.Fatalf("got cep name length is %d but want %d", len(got), tc.wantLength)
			}
			if got != tc.want {
				t.Fatalf("ep.GenerateCEPName() return %s but want %s", got, tc.want)
			}
		})
	}
}
