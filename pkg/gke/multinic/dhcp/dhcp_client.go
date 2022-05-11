/*
Copyright 2021 Google LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package dhcp

import (
	"fmt"
	"net"
	"net/rpc"
	"path/filepath"
	"strings"

	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/containernetworking/cni/pkg/skel"
	cnitypes "github.com/containernetworking/cni/pkg/types"
	ipam "github.com/containernetworking/cni/pkg/types/100"
	networkv1 "gke-internal.googlesource.com/anthos-networking/apis/v2/network/v1"
	"k8s.io/utils/pointer"
)

const (
	defaultDHCPSocketPath = "/run/dhcp/dhcp.sock"
	// DHCP Plugin will allow lease to expire instead of sending DHCP Release packet
	leaseExpireArgs = "leaseExpire=true"
	// when Dst in a route is empty (type netlink.IPNet), Dst.String() returns "<nil>". This is used to
	// determine if Dst is empty in a route
	nilDstString = "<nil>"
)

var (
	logger = logging.DefaultLogger.WithField(logfields.LogSubsys, "dhcp-client")
)

// DHCPClient interface defines the methods necessary to talk to the DHCPPlugin
type DHCPClient interface {
	// GetDHCPResponse sends a request to the DHCPPlugin for an IP allocation
	GetDHCPResponse(containerID, netns, ifname, parentInt string, macAddress *string) (*DHCPResponse, error)
	// Release sends a request to the DHCPPlugin to stop maintaining the lease for the given interface
	Release(containerID, netns, ifname string, letLeaseExpire bool) error
}

// dhcpClient is a rpc Client to query and request DHCP leases from the DHCP plugin
type dhcpClient struct {
	mu         lock.Mutex
	client     *rpc.Client
	socketPath string
}

type DHCPResponse struct {
	//IPAddresses are the ip addresses that have been leased for this interface
	IPAddresses []*net.IPNet
	//Routes are the custom routes for the Network this interface connects to
	Routes []networkv1.Route
	// DNS Config has the Nameservers and Searches specific to the Network this interface connects to
	DNSConfig *networkv1.DNSConfig
	// Gateway4 is the default gateway for the Network this interface is connecting to
	Gateway4 *string
}

// NewDHCPClient returns an instance of DHCPClient with default DHCP socket
func NewDHCPClient() DHCPClient {
	return newDHCPClientWithSocket(defaultDHCPSocketPath)
}

// newDHCPClientWithSocket initializes and returns an instance of DHCPClient with the given socket.
func newDHCPClientWithSocket(socket string) DHCPClient {
	dc := &dhcpClient{
		socketPath: socket,
	}

	err := dc.ensureRPCClient()
	if err != nil {
		logger.Infof("failed to listen on socket %s: %s", defaultDHCPSocketPath, err)
	}
	return dc
}

func (dc *dhcpClient) ensureRPCClient() error {
	dc.mu.Lock()
	defer dc.mu.Unlock()

	if dc.client != nil {
		return nil
	}

	client, err := rpc.DialHTTP("unix", dc.socketPath)
	if err != nil {
		return fmt.Errorf("error dialing socket %s: %w", dc.socketPath, err)
	}
	dc.client = client
	return nil
}

// GetDHCPRelease calls DHCP.Allocate and converts the ipam result into a DHCP response
// that contains, ip, gateway, routes, and dns information
func (dc *dhcpClient) GetDHCPResponse(containerID, netns, ifname, parentIfName string, macAddress *string) (*DHCPResponse, error) {
	result := &ipam.Result{CNIVersion: ipam.ImplementedSpecVersion}
	resp := &DHCPResponse{}
	args := generateCmdArgs(containerID, netns, ifname, parentIfName, macAddress)
	if err := dc.rpcCall("DHCP.Allocate", args, result); err != nil {
		return resp, fmt.Errorf("errored in rpc call DHCP.Allocate: %w", err)
	}

	resp.IPAddresses, resp.Gateway4 = parseIPAndGateway(result.IPs)
	resp.Routes = parseRoutes(result.Routes)
	resp.DNSConfig = parseDNSConfig(result.DNS)

	return resp, nil
}

// Release calls DHCP.Release on the dhcp plugin
func (dc *dhcpClient) Release(containerID, netns, ifname string, letLeaseExpire bool) error {
	args := generateCmdArgs(containerID, netns, ifname, "", nil)
	if letLeaseExpire {
		args.Args = leaseExpireArgs
	}
	result := struct{}{}
	if err := dc.rpcCall("DHCP.Release", args, &result); err != nil {
		return fmt.Errorf("errored in rpc call DHCP.Release: %w", err)
	}

	return nil
}

func (dc *dhcpClient) rpcCall(method string, args *skel.CmdArgs, result interface{}) error {
	if err := dc.ensureRPCClient(); err != nil {
		return fmt.Errorf("failed to connect to socket: %w", err)
	}
	netns, err := filepath.Abs(args.Netns)
	if err != nil {
		return fmt.Errorf("failed to make %q an absolute path: %w", args.Netns, err)
	}
	args.Netns = netns

	err = dc.client.Call(method, args, result)
	if err != nil {
		return fmt.Errorf("error calling %s: %w", method, err)
	}
	return nil
}

func parseIPAndGateway(cfg []*ipam.IPConfig) ([]*net.IPNet, *string) {
	if len(cfg) == 0 {
		return nil, nil
	}

	var gw *string
	if cfg[0].Gateway != nil {
		gw = pointer.StringPtr(cfg[0].Gateway.String())
	}

	return []*net.IPNet{&cfg[0].Address}, gw
}

func parseRoutes(routes []*cnitypes.Route) []networkv1.Route {
	var convertedRoutes []networkv1.Route
	for _, route := range routes {
		if route.Dst.String() != nilDstString {
			convertedRoutes = append(convertedRoutes, networkv1.Route{To: route.Dst.String()})
		}
	}
	return convertedRoutes
}

func parseDNSConfig(dns cnitypes.DNS) *networkv1.DNSConfig {
	if len(dns.Nameservers) == 0 {
		return nil
	}
	return &networkv1.DNSConfig{
		Nameservers: dns.Nameservers,
		Searches:    dns.Search,
	}
}

func generateCmdArgs(containerID, netns, ifname, parentInt string, macAddress *string) *skel.CmdArgs {
	dhcpConf := fmt.Sprintf(`{
  "cniVersion": "0.0.1",
  "name": "dhcpplugin",
  "type": "dhcpplugin",
  "ipam": {
    "type": "dhcp",
    "daemonSocketPath": "%s"
  }
}`, defaultDHCPSocketPath)

	args := &skel.CmdArgs{
		ContainerID: containerID,
		Netns:       netns,
		IfName:      ifname,
		StdinData:   []byte(dhcpConf),
	}
	var argList []string

	if parentInt != "" {
		argList = append(argList, fmt.Sprintf("parentInterface=%s", parentInt))
	}

	if macAddress != nil && *macAddress != "" {
		argList = append(argList, fmt.Sprintf("macAddress=%s", *macAddress))
	}
	if len(argList) > 0 {
		args.Args = strings.Join(argList, ";")
	}

	return args
}
