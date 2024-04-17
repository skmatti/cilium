package translate

import (
	clusterpb "github.com/cilium/proxy/go/envoy/config/cluster/v3"
	"gke-internal.googlesource.com/kon/pkg/model"
)

// ParseClusters parses the given clusters and populate the metadata of the given services
func ParseClusters(servicesByIP map[string]*model.Service, clusters []*clusterpb.Cluster) map[string]*model.Service {
	for _, cluster := range clusters {
		// Validate Cluster is expected type.
		if cluster.GetType() != clusterpb.Cluster_EDS {
			Log.Debugf("Unexpected cluster discovery type %v in response: want EDS", cluster.GetType())
			continue
		}
		if cluster.GetEdsClusterConfig().GetEdsConfig().GetAds() == nil {
			Log.Debugf("Unexpected EDSConfig type in CDS response: %+v, want Ads", cluster.GetEdsClusterConfig().GetEdsConfig())
			continue
		}
		// Once TD exports service metadata and spec in CDS it would be parsed below.
	}
	return servicesByIP
}
