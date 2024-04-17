package translate

import (
	"gke-internal.googlesource.com/kon/pkg/model"

	listenerpb "github.com/cilium/proxy/go/envoy/config/listener/v3"
	tcppb "github.com/cilium/proxy/go/envoy/extensions/filters/network/tcp_proxy/v3"
	"github.com/sirupsen/logrus"
)

// Expose the variable to let the caller replace it with their own logger
var Log = logrus.NewEntry(logrus.New())

func SetLogger(logger *logrus.Entry) {
	Log = logger
}

// ParseListner parses the given listener and returns parsed services by their IP addresses.
func ParseListner(listener *listenerpb.Listener) map[string]*model.Service {
	servicesByIP := make(map[string]*model.Service)
	for _, chain := range listener.GetFilterChains() {
		addrs := chain.GetFilterChainMatch().GetPrefixRanges()
		if len(addrs) != 1 {
			continue
		}
		ip := addrs[0].AddressPrefix

		// A unique pair of address and port maps to only one BackendService, so there would be only one filter.
		if len(chain.GetFilters()) != 1 {
			Log.Warningf("Number of the filters should be one in the chain %s, got %d", chain.Name, len(chain.GetFilters()))
			continue
		}
		filter := chain.GetFilters()[0]

		port := chain.GetFilterChainMatch().GetDestinationPort().GetValue()

		conf := filter.GetTypedConfig()
		if conf == nil {
			Log.Debugf("No typed config in Listener filter.")
			continue
		}

		tcpProxy := &tcppb.TcpProxy{}
		if err := conf.UnmarshalTo(tcpProxy); err != nil {
			Log.Warningf("Failed to unmarshal TypedConfig in LDS: %v", err)
			continue
		}
		xDSClusterName := tcpProxy.GetCluster()
		// If cluster is empty, try to read WeightedClusters to get BackendService.
		if xDSClusterName == "" {
			weightedClusters := tcpProxy.GetWeightedClusters().GetClusters()
			if len(weightedClusters) != 1 {
				Log.Infof("The cluster name is empty and the number of weighted clusters should be one in the chain %s, got %d", chain.Name, len(weightedClusters))
				continue
			}
			xDSClusterName = weightedClusters[0].GetName()
			if xDSClusterName == "" {
				Log.Infof("Cluster name is not set in the weighted clusters in the chain %s", chain.Name)
				continue
			}
		}
		s := servicesByIP[ip]
		if s == nil {
			s = &model.Service{
				IP: ip,
			}
			servicesByIP[ip] = s
		}
		s.Ports = append(s.Ports, model.ServicePort{
			Port:       port,
			XDSCluster: xDSClusterName,
		})
	}
	return servicesByIP
}
