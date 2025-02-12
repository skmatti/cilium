package cmd

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/containernetworking/cni/pkg/skel"
)

func TestGKEMNEndpointConfiguration(t *testing.T) {
	inputJSON := []byte(`
	{
		"cniVersion": "0.3.1",
		"type": "cilium-cni",
		"gcp": {
			"networks": [
			{
				"name": "blue-network",
				"interface": "eth1",
				"ipam": {
				"type": "host-local",
				"ranges": [
					[
					{
						"subnet": "10.92.1.0/26"
					}
					]
				],
				"routes": [
					{
					"dst": "10.0.0.0/24"
					}
				],
				"dataDir": "/tmp/blue-network"
				}
			},
			{
				"name": "green-network",
				"interface": "eth2",
				"ipam": {
				"type": "host-local",
				"ranges": [
					[
					{
						"subnet": "10.92.2.0/26"
					}
					]
				],
				"routes": [
					{
					"dst": "10.1.0.0/24"
					}
				],
				"dataDir": "/tmp/green-network"
				}
			}
			]
		},
		"runtimeConfig": {
			"io.kubernetes.cri.pod-annotations": {
			"kubernetes.io/config.seen": "2025-01-22T22:50:00.990826542Z",
			"kubernetes.io/config.source": "api",
			"networking.gke.io/default-interface": "eth0",
			"networking.gke.io/interfaces": "[\n { \"interfaceName\":\"eth0\", \"network\":\"default\" },\n { \"interfaceName\":\"eth1\", \"network\":\"blue-network\" }\n, { \"interfaceName\":\"eth2\", \"network\":\"green-network\" }\n]"

			}
		}
	}
	`)

	// Expected output JSONs
	expectedJSONs := [][]byte{
		[]byte(`{
			"cniVersion": "0.3.1",
			"name": "blue-network",
			"type": "cilium-cni",
			"ipam": {
				"type": "host-local",
				"ranges": [
					[{"subnet": "10.92.1.0/26"}]
				],
				"routes": [
					{"dst": "10.0.0.0/24"}
				],
				"dataDir": "/tmp/blue-network"
			}
		}`),
		[]byte(`{
			"cniVersion": "0.3.1",
			"name": "green-network",
			"type": "cilium-cni",
			"ipam": {
				"type": "host-local",
				"ranges": [
					[{"subnet": "10.92.2.0/26"}]
				],
				"routes": [
					{"dst": "10.1.0.0/24"}
				],
				"dataDir": "/tmp/green-network"
			}
		}`),
	}

	cfg := GoogleConfigurator{}

	ep_configs, err := cfg.GetConfigurations(ConfigurationParams{
		Args: &skel.CmdArgs{
			StdinData: inputJSON,
		},
	})
	if err != nil {
		t.Fatalf("Expected no error from GetConfiguration, but got %v", err)
	}

	var outputJSONs [][]byte
	for _, epConf := range ep_configs {
		if googleConfig, ok := epConf.(*GoogleEndpointConfiguration); ok {
			outputJSONs = append(outputJSONs, googleConfig.IPAMJson)
		}
	}

	if len(outputJSONs) != len(expectedJSONs) {
		t.Fatalf("Expected %d output JSONs, but got %d", len(expectedJSONs), len(outputJSONs))
	}

	for i, outputJSON := range outputJSONs {
		var outputData, expectedData map[string]interface{}
		if err := json.Unmarshal(outputJSON, &outputData); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(expectedJSONs[i], &expectedData); err != nil {
			t.Fatal(err)
		}

		if !reflect.DeepEqual(outputData, expectedData) {
			t.Errorf("Output JSON %d does not match expected JSON\nExpected: %s\nGot: %s", i+1, expectedJSONs[i], outputJSON)
		}
	}

}

// TestGKEMNEndpointConfigurationNoNetworksInPods tests the case where no network interfaces are specified in pods' annotation, but the node have the corresponding networks available.
func TestGKEMNEndpointConfigurationNoNetworksInPods(t *testing.T) {
	inputJSON := []byte(`
	{
		"cniVersion": "0.3.1",
		"type": "cilium-cni",
		"gcp": {
			"networks": [
			{
				"name": "blue-network",
				"interface": "eth1",
				"ipam": {
				"type": "host-local",
				"ranges": [
					[
					{
						"subnet": "10.92.1.0/26"
					}
					]
				],
				"routes": [
					{
					"dst": "10.0.0.0/24"
					}
				],
				"dataDir": "/tmp/blue-network"
				}
			}
			]
		},
		"runtimeConfig": {
			"io.kubernetes.cri.pod-annotations": {
			"kubernetes.io/config.seen": "2025-01-22T22:50:00.990826542Z",
			"kubernetes.io/config.source": "api",
			"networking.gke.io/default-interface": "eth0"
			}
		}
	}
	`)

	cfg := GoogleConfigurator{}

	_, err := cfg.GetConfigurations(ConfigurationParams{
		Args: &skel.CmdArgs{
			StdinData: inputJSON,
		},
	})
	if err != nil {
		t.Fatalf("Expected no error from GetConfiguration, but got %v", err)
	}

}

// TestGKEMNEndpointDefaultConfigurator tests the default endpoint configurator
func TestGKEMNEndpointDefaultConfigurator(t *testing.T) {
	inputJSON := []byte(`
	{
	"cniVersion": "0.3.1",
	"type": "cilium-cni",
	"ipam": {
		"ranges": [
		[
			{
			"subnet": "10.64.5.0/24"
			}
		]
		],
		"routes": [
		{
			"dst": "0.0.0.0/0"
		}
		],
		"type": "host-local"
	}
	}
	`)

	cfg := GoogleConfigurator{}

	ep_configs, err := cfg.GetConfigurations(ConfigurationParams{
		Args: &skel.CmdArgs{
			StdinData: inputJSON,
		},
	})
	if err != nil {
		t.Fatalf("Expected no error from GetConfiguration, but got %v", err)
	}

	if len(ep_configs) != 1 {
		t.Fatalf("Expected 1 endpoint configuration, but got %d", len(ep_configs))
	}

	for _, epConf := range ep_configs {
		if defaultConfig, ok := epConf.(*defaultEndpointConfiguration); ok {
			if defaultConfig.IPAMPool() != "" {
				t.Fatalf("Expected empty IPAM pool, but got %s", defaultConfig.IPAMPool())
			}
		}
	}
}
