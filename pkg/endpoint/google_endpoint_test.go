package endpoint

import (
	"testing"

	multinicep "github.com/cilium/cilium/pkg/gke/multinic/endpoint"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/testutils"
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
	testutils.PrivilegedTest(t)

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

func TestPopulateNodeNetwork(t *testing.T) {
	testcases := []struct {
		desc            string
		disableMultiNIC bool
		endpoint        *Endpoint
		wantNetwork     string
	}{
		{
			desc: "host endpoint",
			endpoint: &Endpoint{
				OpLabels: labels.OpLabels{
					OrchestrationIdentity: labels.LabelHost,
				},
			},
		},
		{
			desc: "multi nic host endpoint with reserved labels",
			endpoint: &Endpoint{
				OpLabels: labels.OpLabels{
					OrchestrationIdentity: labels.NewReservedMultiNICHostLabels("node-network1"),
				},
			},
			wantNetwork: "node-network1",
		},
		{
			desc:            "multi nic host endpoint with reserved labels (multi NIC host firewall disabled)",
			disableMultiNIC: true,
			endpoint: &Endpoint{
				OpLabels: labels.OpLabels{
					OrchestrationIdentity: labels.NewReservedMultiNICHostLabels("node-network1"),
				},
			},
		},
	}
	for _, tc := range testcases {
		t.Run(tc.desc, func(t *testing.T) {
			if !tc.disableMultiNIC {
				option.Config.EnableGoogleMultiNICHostFirewall = true
				defer func() {
					option.Config.EnableGoogleMultiNICHostFirewall = false
				}()
			}
			tc.endpoint.populateNodeNetwork()
			if tc.endpoint.nodeNetworkName != tc.wantNetwork {
				t.Fatalf("ep.populateNodeNetwork() = %s, want %s", tc.endpoint.nodeNetworkName, tc.wantNetwork)
			}
		})
	}
}
