package datapath

import (
	"net"

	"github.com/cilium/cilium/pkg/datapath/tables"
)

// LoadBalancerNodeAddresses returns all node addresses on which the
// loadbalancer should implement HostPort and NodePort services.
func (a addressFamily) LoadBalancerNodeAddressesV4ByIndex() map[int]net.IP {
	ips := map[int]net.IP{}
	devices, _ := tables.SelectedDevices(a.devices, a.db.ReadTxn())
	for _, dev := range devices {
		for _, addr := range dev.Addrs {
			if addr.Addr.Is4() {
				ips[dev.Index] = addr.AsIP()
			}
		}
	}
	return ips
}
