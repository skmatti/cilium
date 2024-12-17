package cmd

import (
	"encoding/json"
	"errors"
	"net"
	"slices"
	"strings"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/cidr"
	"github.com/cilium/cilium/pkg/datapath/linux/bigtcp"
	gkeTypes "github.com/cilium/cilium/pkg/gke/types"
	ipamOption "github.com/cilium/cilium/pkg/ipam/option"
	"github.com/cilium/cilium/plugins/cilium-cni/types"
	cniTypes "github.com/containernetworking/cni/pkg/types"
)

var (
	errNoPodIP                = errors.New("no pod IP CIDR")
	errInvalidGCPSPec         = errors.New("invalid GCP Spec")
	errInvalidLocalIPv4Router = errors.New("invalid Local Router IPv4 config")
	errInvalidLocalIPv6Router = errors.New("invalid Local Router IPv6 config")
	errDatapathNotPopulated   = errors.New("datapath not populated in GCP Spec")
	errDelegatedPluginNotUsed = errors.New("deleted plugin is not used for IPAM")
)

type rangeSpec struct {
	// Subnet represents the subnet of IP addresses that can be assigned to pods.
	Subnet cniTypes.IPNet `json:"subnet"`
}

type rangeSet []rangeSpec

type ipamConfig struct {
	// Ranges represents the ranges of IP addresses that can be assigned to pods.
	Ranges []rangeSet `json:"ranges"`
}

// The top-level network config that IPAM plugins are passed.
// Creating the Struct based on host-local ipam plugin
// (https://github.com/containernetworking/plugins/blob/abfac4a938866b6184441d02ad49544d10931fe1/plugins/ipam/host-local/backend/allocator/config.go#L29)
type netConfig struct {
	// IPAM represents the IPAM configuration section of the CNI config file.
	IPAM ipamConfig `json:"ipam"`
}

func getIpamConfig(stdinData []byte) (*ipamConfig, error) {
	var n netConfig
	if err := json.Unmarshal(stdinData, &n); err != nil {
		return nil, err
	}
	if len(n.IPAM.Ranges) == 0 || len(n.IPAM.Ranges[0]) == 0 {
		return nil, errNoPodIP
	}
	return &n.IPAM, nil
}

// nodeAddressingFromIPAMConfig parses the ipam data and returns the node addressing information.
func nodeAddressingFromIPAMConfig(gcpSpec gkeTypes.GCPSpec, ipamData *ipamConfig) (*models.NodeAddressing, error) {
	addr := &models.NodeAddressing{}

	if !gcpSpec.EnableIPv4 && !gcpSpec.EnableIPv6 {
		return nil, errInvalidGCPSPec
	}
	if gcpSpec.EnableIPv4 && gcpSpec.LocalRouterIPv4 == "" {
		return nil, errInvalidLocalIPv4Router
	}
	if gcpSpec.EnableIPv6 && gcpSpec.LocalRouterIPv6 == "" {
		return nil, errInvalidLocalIPv6Router
	}

	ipv4AllocRange := ""
	ipv6AllocRange := ""
	for _, ipamRange := range ipamData.Ranges {
		for _, podCIDR := range ipamRange {
			allocRange := cidr.NewCIDR(&net.IPNet{
				IP:   podCIDR.Subnet.IP,
				Mask: podCIDR.Subnet.Mask,
			})

			// Looking at the first address in ranges to keep it consistent with how NoeAddressing is updated in pkg/node/address.go (GetNodeAddressing())
			if allocRange.IP.To4() != nil && ipv4AllocRange == "" {
				ipv4AllocRange = allocRange.String()
			} else if ipv6AllocRange == "" {
				ipv6AllocRange = allocRange.String()
			}
		}
	}

	if gcpSpec.EnableIPv4 {
		addr.IPV4 = &models.NodeAddressingElement{
			Enabled:    gcpSpec.EnableIPv4,
			IP:         gcpSpec.LocalRouterIPv4,
			AllocRange: ipv4AllocRange,
		}
	}

	if gcpSpec.EnableIPv6 {
		addr.IPV6 = &models.NodeAddressingElement{
			Enabled:    gcpSpec.EnableIPv6,
			IP:         gcpSpec.LocalRouterIPv6,
			AllocRange: ipv6AllocRange,
		}
	}

	return addr, nil
}

// createDaemonConfFromCNIConfig parses stdin and GCPSpec data and fills in the sections of DaemonConfigurationStatus necessary for interface (veth) creation.
func createDaemonConfFromCNIConfig(n *types.NetConf, ipamData *ipamConfig) (*models.DaemonConfigurationStatus, error) {
	daemonConfig := &models.DaemonConfigurationStatus{}

	if n.GCP.DatapathMode == "" {
		return nil, errDatapathNotPopulated
	}
	daemonConfig.DatapathMode = models.DatapathMode(n.GCP.DatapathMode)

	if (n.GCP.IpamMode != ipamOption.IPAMDelegatedPlugin) && (n.IPAM.Type != "host-local") {
		return nil, errDelegatedPluginNotUsed
	}
	daemonConfig.IpamMode = ipamOption.IPAMDelegatedPlugin

	var err error
	if daemonConfig.Addressing, err = nodeAddressingFromIPAMConfig(n.GCP, ipamData); err != nil {
		return nil, err
	}

	// Fast start would be disabled in CNI config file if the below flags are different in cilium-config configmap
	daemonConfig.GROMaxSize = int64(bigtcp.GetGROMaxSize())
	daemonConfig.GSOMaxSize = int64(bigtcp.GetGSOMaxSize())
	daemonConfig.GROIPV4MaxSize = int64(bigtcp.GetGROMaxSize())
	daemonConfig.GSOIPV4MaxSize = int64(bigtcp.GetGSOMaxSize())
	daemonConfig.RouteMTU = int64(n.MTU)
	daemonConfig.DeviceMTU = int64(n.MTU)
	daemonConfig.IPLocalReservedPorts = ""
	return daemonConfig, nil
}

// isFastStartEnabled returns true if fast start is enabled for the pod's namespace.
func isFastStartEnabled(n *types.NetConf, podNamespace string) bool {
	var fs string
	fastStartEnabled := false
	if n.GCP.FastStartNamespaces != "" {
		fs = n.GCP.FastStartNamespaces
	} else {
		fs = n.FastStartNamespaces
	}

	if fs == "" {
		return false
	}
	if fs == "@all" {
		fastStartEnabled = true
	} else {
		fastStartNamespacesList := strings.Split(fs, ",")
		if slices.Contains(fastStartNamespacesList, podNamespace) {
			fastStartEnabled = true
		}
	}
	return fastStartEnabled
}
