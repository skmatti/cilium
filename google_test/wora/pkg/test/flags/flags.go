package flags

import (
	"flag"
	"fmt"

	"gke-internal.googlesource.com/third_party/cilium/google_test/wora/e2e/pkg/test/common"
)

var (
	clusterTypeFlag = flag.String("cluster-type", "", "cluster type the test is running against")
)

func ClusterType() (common.ClusterType, error) {
	parsedClusterType := common.ClusterType(*clusterTypeFlag)
	// If no clusterType specified, default to infra cluster
	if *clusterTypeFlag == "" {
		return common.ClusterTypeInfra, nil
	} else {
		switch parsedClusterType {
		case common.ClusterTypeInfra, common.ClusterTypePerimeter:
			return parsedClusterType, nil
		default:
			return "", fmt.Errorf("invalid cluster type: %s", *clusterTypeFlag)
		}
	}
}
