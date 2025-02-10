package cmd

import (
	"encoding/json"
	"fmt"
	"net"
	"path/filepath"
	"strings"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/datapath/linux/route"
	gkeTypes "github.com/cilium/cilium/pkg/gke/types"
	ipamOption "github.com/cilium/cilium/pkg/ipam/option"
)

// GoogleConfigurator is the default endpoint configurator. It configures a
// single endpoint for the interface name provided by the CNI ADD invocation,
// using an auto-selected IPAM pool.
type GoogleConfigurator struct {
}

type GoogleEndpointConfiguration struct {
	// ConfigurationParams contains the parameters passed to the endpoint configurator.
	ConfigurationParams
	// NetworkName is the name of the network.
	NetworkName string
	// IPAMJson is the JSON representation of the network to be passed to the IPAM plugin.
	IPAMJson []byte
	//  is the name of the interface.
	Interface Interface
	// Routes is the list of routes to be added to the interface.
	Routes []route.Route
}

type Interface struct {
	// InterfaceName is the name of the interface.
	InterfaceName string `json:"interfaceName"`
	// Network is the name of the network which the interface belongs to.
	Network string `json:"network"`
}

// IPAMPool implements EndpointConfiguration. We don't use IPAM pools in GKE.
func (c *GoogleEndpointConfiguration) IPAMPool() string {
	return ""
}

// IfName implements EndpointConfiguration.
func (c *GoogleEndpointConfiguration) IfName() string {
	return c.Interface.InterfaceName
}

// PrepareEndpoint implements EndpointConfiguration.
func (c *GoogleEndpointConfiguration) PrepareEndpoint(ipam *models.IPAMResponse) (cmd *CmdState, ep *models.EndpointChangeRequest, err error) {
	ep = &models.EndpointChangeRequest{
		ContainerID:            c.Args.ContainerID,
		Labels:                 models.Labels{},
		State:                  models.EndpointStateWaitingDashForDashIdentity.Pointer(),
		Addressing:             &models.AddressPair{},
		K8sPodName:             string(c.CniArgs.K8S_POD_NAME),
		K8sNamespace:           string(c.CniArgs.K8S_POD_NAMESPACE),
		K8sUID:                 string(c.CniArgs.K8S_POD_UID),
		ContainerInterfaceName: c.IfName(),
		DatapathConfiguration:  &models.EndpointDatapathConfiguration{},
		// Constructs the full path of network namespace on the anetd pod.
		// /host is the mounted volume of the host's directory
		NetworkNamespace:         filepath.Join("/host", c.Args.Netns),
		DisableLegacyIdentifiers: true,
	}

	if c.Conf.IpamMode == ipamOption.IPAMDelegatedPlugin {
		// Prevent cilium agent from trying to release the IP when the endpoint is deleted.
		ep.DatapathConfiguration.ExternalIpam = true
	}

	state := &CmdState{
		IP4routes: c.Routes,
	}

	return state, ep, nil

}

// GetConfigurations returns a list of endpoint configurations for the default network and the additional networks.
// The presence of the nettworks in the "gcp" section of the plugin data indicates that the networks are valid on the host.
func (c *GoogleConfigurator) GetConfigurations(p ConfigurationParams) ([]EndpointConfiguration, error) {
	var cniConfig gkeTypes.CNIConfig
	var epConfigs []EndpointConfiguration

	if err := json.Unmarshal(p.Args.StdinData, &cniConfig); err != nil {
		return nil, fmt.Errorf("failed to unmarshal plugin data: %w", err)
	}

	networkIfaces, err := extractNetworkInterfaces(cniConfig.RuntimeConfig)
	if err != nil {
		return nil, err
	}

	epConfigs, err = processNetworks(cniConfig, networkIfaces, p)
	if err != nil {
		return nil, err
	}

	// We should not return any endpoint configurations if parsing fails at any point.
	epConfigs = append(epConfigs, &defaultEndpointConfiguration{
		ConfigurationParams: p,
	})
	return epConfigs, nil
}

func marshalNetworks(network gkeTypes.Network) ([]byte, error) {
	networksJSON, err := json.Marshal(network) // Use MarshalIndent for pretty printing
	if err != nil {
		return nil, fmt.Errorf("error marshalling networks: %w", err)
	}
	return networksJSON, nil
}

// extractNetworkInterfaces collects the network interface names (eth0, eth1, etc.) and their corresponding network name (default, blue-network, etc) from the runtimeConfig section
func extractNetworkInterfaces(rt gkeTypes.RuntimeConfig) (map[string]string, error) {
	networkIfaces := make(map[string]string)

	if rt.PodAnnotations == nil || rt.PodAnnotations.NetworkingGKEIOInterfaces == "" {
		return networkIfaces, nil
	}

	ifaceString := strings.ReplaceAll(rt.PodAnnotations.NetworkingGKEIOInterfaces, "\n", "")
	var interfaces []Interface
	if err := json.Unmarshal([]byte(ifaceString), &interfaces); err != nil {
		return nil, fmt.Errorf("failed to unmarshal network interfaces: %w", err)
	}

	for _, iface := range interfaces {
		networkIfaces[iface.Network] = iface.InterfaceName
	}

	return networkIfaces, nil

}

// processNetworks processes the networks in the plugin data and creates endpoint configurations for each network.
func processNetworks(cniConfig gkeTypes.CNIConfig, networkIfaces map[string]string, p ConfigurationParams) ([]EndpointConfiguration, error) {
	epConfigs := []EndpointConfiguration{}

	for _, network := range cniConfig.GCP.Networks {
		// Set the fields that are needed for IPAMJSON consumed by host-local
		network.CNIVersion = cniConfig.CNIVersion
		network.Interface = ""
		network.Type = "cilium-cni"
		ep_config, err := createEndpointConfiguration(network, networkIfaces, p)
		if err != nil {
			return nil, err
		}
		epConfigs = append(epConfigs, ep_config)
	}

	return epConfigs, nil
}

// createEndpointConfiguration creates an endpoint configuration for a network.
func createEndpointConfiguration(network gkeTypes.Network, containerInterface map[string]string, p ConfigurationParams) (*GoogleEndpointConfiguration, error) {
	if iface, ok := containerInterface[network.Name]; ok {
		outputJSON, err := marshalNetworks(network)
		if err != nil {
			return nil, err
		}
		routes, err := parseIPRoutes(network.IPAM.Routes)
		if err != nil {
			return nil, err
		}
		return &GoogleEndpointConfiguration{
			NetworkName:         network.Name,
			IPAMJson:            outputJSON,
			ConfigurationParams: p,
			Interface: Interface{
				InterfaceName: iface,
				Network:       network.Name,
			},
			Routes: routes,
		}, nil
	}
	return nil, fmt.Errorf("network interface not found for network %s", network.Name)
}

func parseIPRoutes(routes []gkeTypes.Route) ([]route.Route, error) {
	var res []route.Route
	for _, rt := range routes {
		ip, ipNet, err := net.ParseCIDR(rt.Dst)
		if err != nil {
			return nil, fmt.Errorf("failed to parse CIDR: %v", err)
		}
		if ones, _ := ipNet.Mask.Size(); ones == 0 {
			return nil, fmt.Errorf("CIDR length must be over 0: %s", rt.Dst)
		}
		if ip.To4() == nil {
			return nil, fmt.Errorf("ipv6 route %q is not supported", rt.Dst)
		}
		res = append(res, route.Route{
			Prefix: *ipNet,
		})
	}
	return res, nil
}
