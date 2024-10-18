package alignchecker

import (
	"github.com/cilium/cilium/pkg/maps/multinetworking"
)

func registerToCheckGoogleMaps() {

	registerToCheck(map[string][]any{
		"multi_nic_dev_key":      {multinetworking.Key{}},
		"multi_nic_dev_info":     {multinetworking.MultiNICDevInfo{}},
		"host_dev_routing_key":   {multinetworking.HostDevRoutingKey{}},
		"host_dev_routing_entry": {multinetworking.HostDevRoutingEntry{}},
	})
}
