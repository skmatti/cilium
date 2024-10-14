package cmd

import (
	"github.com/cilium/cilium/pkg/endpoint"
)

func (d *Daemon) PreAllocateIPsForRestoredMultiNICEndpoints(eps []*endpoint.Endpoint) error {
	for _, ep := range eps {
		if !ep.IsMultiNIC() || ep.ExternalDHCPEnabled() {
			continue
		}
		if err := d.AllocateIP(ep.GetIPv4Address(), ep.K8sPodName); err != nil {
			// There would be no allocators for cases when `externalDHCP: false` or static IPs (kubevirt's case).
			// We are only logging a warning here to avoid anetd crash loop back in cluster upgrade scenarios for
			// such workloads.
			// TODO(b/336614270) - revisit this when moving to hive cell, fetch pods and determine if pod is connected to IPAMMode: Internal network.
			ep.Logger(daemonSubsys).Warningf("endpoint is multi-nic but no allocators were found to occupy its IP address %s, may be endpoint IP is static", ep.GetIPv4Address())
		}
	}
	return nil
}
