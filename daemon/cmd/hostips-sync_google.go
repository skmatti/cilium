// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"net"

	ippkg "github.com/cilium/cilium/pkg/ip"
)

func (s *syncHostIPs) podGatewayIPv4() (net.IP, bool) {
	if !s.params.Config.RegisterIPv4PodGateway {
		return nil, false
	}

	// ipam setup (see daemon.ConfigureIPAM) ensures that AllocationCIDR is
	// initialized.
	ipv4Alloc := s.params.Datapath.LocalNodeAddressing().IPv4().AllocationCIDR()
	if ipv4Alloc.IPNet != nil {
		gwIP := ippkg.GetIPAtIndex(*ipv4Alloc.IPNet, 1)
		return gwIP, true
	}
	return nil, false
}
