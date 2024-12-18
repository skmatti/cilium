package cmd

import (
	"fmt"

	"github.com/cilium/cilium/pkg/endpoint"
)

func (d *Daemon) PreAllocateIPsForRestoredMultiNICEndpoints(eps []*endpoint.Endpoint) error {
	for _, ep := range eps {
		if !ep.IsMultiNIC() || ep.ExternalDHCPEnabled() {
			continue
		}
		if err := d.AllocateIP(ep.GetIPv4Address(), ep.K8sPodName); err != nil {
			return fmt.Errorf("error while allocating IP of the multi-nic endpoint: %v", err)
		}
	}
	return nil
}
