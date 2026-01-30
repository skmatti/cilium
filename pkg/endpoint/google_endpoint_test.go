package endpoint

import (
	"testing"

	"github.com/cilium/cilium/api/v1/models"
	multinicep "github.com/cilium/cilium/pkg/gke/multinic/endpoint"
	"github.com/cilium/cilium/pkg/gke/multinic/multinicconfig"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/testutils"
)

const (
	podName         = "fooPod"
	containerIfName = "fooEth0"
	// podNameWithMaxLength has 236 character length which should generate
	// the cep name with maximum length (253) when using containerIfName above
	// and no need to truncate.
	podNameWithMaxLength = "FWVQZcvBFvHEVVmdhCeAaCpDnWftvyqMasxPHOsuswqGTgIoTqddHnASNVdfsjiHkdmkxOvDziEwXShFFWUVcHCuAJiHZKjXCDCeKkAnMWaSAefKPjInundJPkurZxRXaWAQOejvCrRmlZAgIYIcWWLncKsnxYGDurlAyQZGKVFjctaenmZeTVVvCZxASFGgOnnSAABkujSXaRajzGjssGCrgKWxlZQYVjeLEZezscql"
)

func TestGetK8sCEPName(t *testing.T) {
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
				K8sPodName:      podName,
				containerIfName: containerIfName,
				deviceType:      multinicep.EndpointDeviceMACVTAP,
			},
			want:       "fooPod-fooEth0-d34eb6b4",
			wantLength: 23,
		},
		{
			desc: "multinic endpoint with maximum length pod name",
			endpoint: &Endpoint{
				K8sPodName:      podNameWithMaxLength,
				containerIfName: containerIfName,
				deviceType:      multinicep.EndpointDeviceMACVTAP,
			},
			want:       podNameWithMaxLength + "-fooEth0-f73e6eb0",
			wantLength: 253,
		},
		{
			desc: "multinic endpoint need truncate",
			endpoint: &Endpoint{
				K8sPodName:      podNameWithMaxLength + "0",
				containerIfName: containerIfName,
				deviceType:      multinicep.EndpointDeviceMACVTAP,
			},
			want:       podNameWithMaxLength + "-fooEth0-3f4d52c3",
			wantLength: 253,
		},
		{
			desc: "multinic endpoint with old naming scheme disabled",
			endpoint: &Endpoint{
				K8sPodName:               podName,
				containerIfName:          "eth1",
				deviceType:               multinicep.EndpointDeviceMACVTAP,
				disableLegacyIdentifiers: true,
			},
			want:       podName + "-" + "eth1",
			wantLength: 11,
		},
	}
	for _, tc := range testcases {
		t.Run(tc.desc, func(t *testing.T) {
			if tc.endpoint.GetDeviceType() != multinicep.EndpointDeviceVETH {
				multinicconfig.GlobalConfig.EnableGoogleMultiNIC = true
				defer func() {
					multinicconfig.GlobalConfig.EnableGoogleMultiNIC = false
				}()
			}
			got := tc.endpoint.GetK8sCEPName()
			if len(got) != tc.wantLength {
				t.Fatalf("got cep name length is %d but want %d", len(got), tc.wantLength)
			}
			if got != tc.want {
				t.Fatalf("ep.GenerateCEPName() return %s but want %s", got, tc.want)
			}
		})
	}
}

func TestSetGoogleConfig(t *testing.T) {
	// Save original values to restore them later
	origAllowDisableSIP := option.Config.AllowDisableSourceIPValidation

	defer func() {
		// Restore original values
		option.Config.AllowDisableSourceIPValidation = origAllowDisableSIP
	}()

	tests := []struct {
		name                         string
		allowDisableSIP              bool
		disableSipVerificationOnEP   bool
		initialSourceIPVerification  option.OptionSetting
		expectedSourceIPVerification option.OptionSetting
		expectedChanged              bool
	}{
		{
			name:                         "AllowDisableSourceIPValidation is false",
			allowDisableSIP:              false,
			disableSipVerificationOnEP:   true,
			initialSourceIPVerification:  option.OptionEnabled,
			expectedSourceIPVerification: option.OptionEnabled,
			expectedChanged:              false,
		},
		{
			name:                         "AllowDisableSourceIPValidation is true, but DisableSipVerification is false",
			allowDisableSIP:              true,
			disableSipVerificationOnEP:   false,
			initialSourceIPVerification:  option.OptionEnabled,
			expectedSourceIPVerification: option.OptionEnabled,
			expectedChanged:              false,
		},
		{
			name:                         "AllowDisableSourceIPValidation is true and DisableSipVerification is true",
			allowDisableSIP:              true,
			disableSipVerificationOnEP:   true,
			initialSourceIPVerification:  option.OptionEnabled,
			expectedSourceIPVerification: option.OptionDisabled,
			expectedChanged:              true,
		},
		{
			name:                         "Option already disabled, should remain disabled",
			allowDisableSIP:              true,
			disableSipVerificationOnEP:   true,
			initialSourceIPVerification:  option.OptionDisabled,
			expectedSourceIPVerification: option.OptionDisabled,
			expectedChanged:              false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			option.Config.AllowDisableSourceIPValidation = tt.allowDisableSIP

			ep := &Endpoint{
				DatapathConfiguration: models.EndpointDatapathConfiguration{
					DisableSipVerification: tt.disableSipVerificationOnEP,
				},
				Options: option.NewIntOptions(&option.OptionLibrary{}),
			}
			ep.Options.SetValidated(option.SourceIPVerification, tt.initialSourceIPVerification)

			changed := ep.setGoogleConfig()

			if changed != tt.expectedChanged {
				t.Errorf("setGoogleConfig() returned changed = %v, want %v", changed, tt.expectedChanged)
			}

			got := ep.Options.GetValue(option.SourceIPVerification)
			if got != tt.expectedSourceIPVerification {
				t.Errorf("setGoogleConfig() got SourceIPVerification = %v, want %v", got, tt.expectedSourceIPVerification)
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
