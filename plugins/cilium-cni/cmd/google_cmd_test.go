package cmd

import (
	"fmt"
	"net"
	"testing"

	"github.com/cilium/cilium/api/v1/models"
	gkeTypes "github.com/cilium/cilium/pkg/gke/types"
	"github.com/cilium/cilium/plugins/cilium-cni/types"
	cniTypes "github.com/containernetworking/cni/pkg/types"
	"github.com/google/go-cmp/cmp"
)

func TestIsFastStartEnabled(t *testing.T) {
	var checkFastStartTests = []struct {
		name         string
		netConf      types.NetConf
		podNamespace string
		expected     bool
	}{
		{
			name: "namespace_present",
			netConf: types.NetConf{
				FastStartNamespaces: "ns1,ns2",
				GCP: gkeTypes.GCPSpec{
					FastStartNamespaces: "",
				},
			},
			podNamespace: "ns2",
			expected:     true,
		},
		{
			name: "namespace_present_in_gcp_spec",
			netConf: types.NetConf{
				FastStartNamespaces: "",
				GCP: gkeTypes.GCPSpec{
					FastStartNamespaces: "ns1,ns2",
				},
			},
			podNamespace: "ns2",
			expected:     true,
		},
		{
			name: "namespace_absent",
			netConf: types.NetConf{
				FastStartNamespaces: "ns1,ns2",
				GCP: gkeTypes.GCPSpec{
					FastStartNamespaces: "",
				},
			},
			podNamespace: "ns3",
			expected:     false,
		},
		{
			name: "namespace_empty",
			netConf: types.NetConf{
				FastStartNamespaces: "",
				GCP: gkeTypes.GCPSpec{
					FastStartNamespaces: "",
				},
			},
			podNamespace: "ns3",
			expected:     false,
		},
		{
			name: "perfer_gcp_spec",
			netConf: types.NetConf{
				FastStartNamespaces: "ns3",
				GCP: gkeTypes.GCPSpec{
					FastStartNamespaces: "ns1,ns2",
				},
			},
			podNamespace: "ns3",
			expected:     false,
		},
		{
			name: "handle_@all_namespaces",
			netConf: types.NetConf{
				FastStartNamespaces: "@all",
				GCP: gkeTypes.GCPSpec{
					FastStartNamespaces: "",
				},
			},
			podNamespace: "ns3",
			expected:     true,
		},
		{
			name: "handle_@all_in_gcp_spec",
			netConf: types.NetConf{
				FastStartNamespaces: "",
				GCP: gkeTypes.GCPSpec{
					FastStartNamespaces: "@all",
				},
			},
			podNamespace: "ns3",
			expected:     true,
		},
		{
			name: "prefer_@all_in_gcp_spec",
			netConf: types.NetConf{
				FastStartNamespaces: "ns1",
				GCP: gkeTypes.GCPSpec{
					FastStartNamespaces: "@all",
				},
			},
			podNamespace: "ns3",
			expected:     true,
		},
	}
	for _, tt := range checkFastStartTests {
		t.Run(tt.name, func(t *testing.T) {
			if result := isFastStartEnabled(&tt.netConf, tt.podNamespace); result != tt.expected {
				t.Fatalf("isFastStartEnabled want: %v, got: %v", tt.expected, result)
			}
		})
	}
}

func TestCreateDaemonConfFromCNIConfig(t *testing.T) {
	stdin := []byte(`{
		"ipam": {
			"ranges": [
				[{"subnet": "10.120.2.0/24"}]
			]
		}
	}`)
	ipam, err := getIpamConfig(stdin)
	if err != nil {
		t.Fatalf("getIpamConfig want: %v, got: %v", nil, err)
	}
	var daemonConfTests = []struct {
		name    string
		netConf types.NetConf
	}{
		{
			name: "valid_ipv4_input",
			netConf: types.NetConf{
				GCP: gkeTypes.GCPSpec{
					DatapathMode:    "veth",
					IpamMode:        "delegated-plugin",
					EnableIPv4:      true,
					LocalRouterIPv4: "169.254.4.6",
				},
				IPAM: types.IPAM{
					IPAM: cniTypes.IPAM{
						Type: "host-local",
					},
				},
			},
		},
		{
			name: "valid_ipv6_input",
			netConf: types.NetConf{
				GCP: gkeTypes.GCPSpec{
					DatapathMode:    "veth",
					IpamMode:        "delegated-plugin",
					EnableIPv6:      true,
					LocalRouterIPv6: "fe80::8893:b6ff:fe2c:7a0d",
				},
				IPAM: types.IPAM{
					IPAM: cniTypes.IPAM{
						Type: "host-local",
					},
				},
			},
		},
		{
			name: "host_local_ipam",
			netConf: types.NetConf{
				GCP: gkeTypes.GCPSpec{
					DatapathMode:    "veth",
					IpamMode:        "kubernetes",
					EnableIPv4:      true,
					LocalRouterIPv4: "169.254.4.6",
				},
				IPAM: types.IPAM{
					IPAM: cniTypes.IPAM{
						Type: "host-local",
					},
				},
			},
		},
	}
	for _, tt := range daemonConfTests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := createDaemonConfFromCNIConfig(&tt.netConf, ipam); err != nil {
				t.Fatalf("createDaemonConfFromCNIConfig err: %v", err)
			}
		})
	}
}

func TestCreateDaemonConfFromCNIConfig_Errors(t *testing.T) {
	stdin := []byte(`{
		"ipam": {
			"ranges": [
				[{"subnet": "10.120.2.0/24"}]
			]
		}
	}`)
	ipam, err := getIpamConfig(stdin)
	if err != nil {
		t.Fatalf("getIpamConfig want: %v, got: %v", nil, err)
	}
	var daemonConfTests = []struct {
		name        string
		netConf     types.NetConf
		expectedErr error
	}{
		{
			name: "datapath_empty",
			netConf: types.NetConf{
				GCP: gkeTypes.GCPSpec{
					IpamMode:        "delegated-plugin",
					EnableIPv4:      true,
					LocalRouterIPv4: "169.254.4.6",
				},
				IPAM: types.IPAM{
					IPAM: cniTypes.IPAM{
						Type: "host-local",
					},
				},
			},
			expectedErr: errDatapathNotPopulated,
		},
		{
			name: "delegated_plugin_not_used",
			netConf: types.NetConf{
				GCP: gkeTypes.GCPSpec{
					DatapathMode:    "veth",
					IpamMode:        "kubernetes",
					EnableIPv4:      true,
					LocalRouterIPv4: "169.254.4.6",
				},
				IPAM: types.IPAM{
					IPAM: cniTypes.IPAM{
						Type: "",
					},
				},
			},
			expectedErr: errDelegatedPluginNotUsed,
		},
	}
	for _, tt := range daemonConfTests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := createDaemonConfFromCNIConfig(&tt.netConf, ipam); err != tt.expectedErr {
				t.Fatalf("createDaemonConfFromCNIConfig want: %v, got: %v", tt.expectedErr, err)
			}
		})
	}
}

func TestCreateNodeAddressingFromIPAMConfig(t *testing.T) {
	stdinIPv4 := []byte(`{
		"ipam": {
			"type": "host-local",
			"ranges": [
				[{"subnet": "10.120.2.0/24"}]
			],
			"routes": [
				{"dst": "0.0.0.0/0"}
			]
		}
	}`)
	ipamIPv4, err := getIpamConfig(stdinIPv4)
	if err != nil {
		t.Fatalf("getIpamConfig want: %v, got: %v", nil, err)
	}

	ipv4GCPSpec := gkeTypes.GCPSpec{EnableIPv4: true, LocalRouterIPv4: "169.254.4.6"}
	expectedIPv4Addressing := &models.NodeAddressing{IPV4: &models.NodeAddressingElement{Enabled: true, IP: ipv4GCPSpec.LocalRouterIPv4, AllocRange: "10.120.2.0/24"}}

	stdinIPv6 := []byte(`{
		"ipam": {
			"type": "host-local",
			"ranges": [
				[{"subnet": "fe80::/64"}]
			]
		}
	}`)
	ipamIPv6, err := getIpamConfig(stdinIPv6)
	if err != nil {
		t.Fatalf("getIpamConfig want: %v, got: %v", nil, err)
	}
	ipv6GCPSpec := gkeTypes.GCPSpec{EnableIPv6: true, LocalRouterIPv6: "fe80::8893:b6ff:fe2c:7a0d"}
	expectedIPv6Addressing := &models.NodeAddressing{IPV6: &models.NodeAddressingElement{Enabled: true, IP: ipv6GCPSpec.LocalRouterIPv6, AllocRange: "fe80::/64"}}

	stdinIPv4AndIPv6 := []byte(`{
		"ipam": {
			"type": "host-local",
			"ranges": [
				[{"subnet": "10.120.2.0/24"}],
				[{"subnet": "fe80::/64"}]
			],
			"routes": [
				{"dst": "0.0.0.0/0"}
			]
		}
	}`)
	ipamIPv4AndIPv6, err := getIpamConfig(stdinIPv4AndIPv6)
	if err != nil {
		t.Fatalf("getIpamConfig want: %v, got: %v", nil, err)
	}
	ipv4Andv6GCPSpec := gkeTypes.GCPSpec{EnableIPv4: true, EnableIPv6: true, LocalRouterIPv4: ipv4GCPSpec.LocalRouterIPv4, LocalRouterIPv6: ipv6GCPSpec.LocalRouterIPv6}
	expectedIPv4Andv6Addressing := &models.NodeAddressing{IPV4: expectedIPv4Addressing.IPV4, IPV6: expectedIPv6Addressing.IPV6}

	var nodeAddrTests = []struct {
		name      string
		gcp       gkeTypes.GCPSpec
		ipam      *ipamConfig
		expected  *models.NodeAddressing
		expectErr error
	}{
		{
			name:      "valid_ipv4",
			gcp:       ipv4GCPSpec,
			ipam:      ipamIPv4,
			expected:  expectedIPv4Addressing,
			expectErr: nil,
		},
		{
			name:      "valid_ipv6",
			gcp:       ipv6GCPSpec,
			ipam:      ipamIPv6,
			expected:  expectedIPv6Addressing,
			expectErr: nil,
		},
		{
			name:      "invalid_GCP_Spec_IP",
			gcp:       gkeTypes.GCPSpec{},
			ipam:      ipamIPv4,
			expected:  nil,
			expectErr: errInvalidGCPSPec,
		},
		{
			name: "invalid_GCP_Spec_IPv4",
			gcp: gkeTypes.GCPSpec{
				EnableIPv4: true,
			},
			ipam:      ipamIPv4,
			expected:  nil,
			expectErr: errInvalidLocalIPv4Router,
		},
		{
			name: "invalid_GCP_Spec_IPv6",
			gcp: gkeTypes.GCPSpec{
				EnableIPv6: true,
			},
			ipam:      ipamIPv6,
			expected:  nil,
			expectErr: errInvalidLocalIPv6Router,
		},
		{
			name:      "both_ipv4_ipv6",
			gcp:       ipv4Andv6GCPSpec,
			ipam:      ipamIPv4AndIPv6,
			expected:  expectedIPv4Andv6Addressing,
			expectErr: nil,
		},
	}
	for _, tt := range nodeAddrTests {
		t.Run(tt.name, func(t *testing.T) {
			var out *models.NodeAddressing
			var err error
			if out, err = nodeAddressingFromIPAMConfig(tt.gcp, tt.ipam); err != tt.expectErr {
				t.Fatalf("node addressing err: %v", err)
			}
			if diff := cmp.Diff(out, tt.expected); diff != "" {
				t.Fatalf("node addressing diff (-want +got):\n%s", diff)
			}
		})
	}
}

func TestGetIPAMConfig(t *testing.T) {

	stdinIPv4 := []byte(`{
		"ipam": {
			"type": "host-local",
			"ranges": [
				[{"subnet": "10.120.2.0/24"}]
			],
			"routes": [
				{"dst": "0.0.0.0/0"}
			]
		}
	}`)
	stdinIPv6 := []byte(`{
		"ipam": {
			"type": "host-local",
			"ranges": [
				[{"subnet": "2001:db8::/32"}]
			]
		}
	}`)

	var ipamTests = []struct {
		name     string
		stdin    []byte
		ipamData *ipamConfig
	}{
		{
			name:  "valid_ipv4_input",
			stdin: stdinIPv4,
			ipamData: &ipamConfig{
				Ranges: []rangeSet{
					{
						rangeSpec{
							Subnet: cniTypes.IPNet{
								IP:   net.ParseIP("10.120.2.0"),
								Mask: net.CIDRMask(24, 32),
							},
						},
					},
				},
			},
		},
		{
			name:  "valid_ipv6_input",
			stdin: stdinIPv6,
			ipamData: &ipamConfig{
				Ranges: []rangeSet{
					{
						rangeSpec{
							Subnet: cniTypes.IPNet{
								IP:   net.ParseIP("2001:db8::"),
								Mask: net.CIDRMask(32, 128),
							},
						},
					},
				},
			},
		},
	}
	for _, tt := range ipamTests {
		t.Run(tt.name, func(t *testing.T) {
			ipam, err := getIpamConfig(tt.stdin)
			if err != nil {
				t.Fatalf("getIpamConfig err: %v", err)
			}
			if diff := cmp.Diff(ipam, tt.ipamData); diff != "" {
				t.Fatalf("ipamData diff (-want +got):\n%s", diff)
			}
		})
	}
}

func TestGetIPAMConfig_Errors(t *testing.T) {
	var ipamTests = []struct {
		name  string
		stdin []byte
		err   error
	}{
		{
			name:  "empty_input",
			stdin: []byte{},
			err:   fmt.Errorf("unexpected end of JSON input"),
		},
		{
			name:  "empty_range",
			stdin: []byte(`{"ipam": {}}`),
			err:   errNoPodIP,
		},
		{
			name: "malformed_input",
			stdin: []byte(`{
				"ipam": {
					"type": "host-local",
					"ranges": [
						[{"subnet": "10.120.2.0/24"}]
				}
			}`),
			err: fmt.Errorf("invalid character '}' after array element"),
		},
	}
	for _, tt := range ipamTests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := getIpamConfig(tt.stdin); err == nil || (err.Error() != tt.err.Error()) {
				t.Fatalf("getIpamConfig want: %v, got: %v", tt.err, err)
			}
		})
	}
}
