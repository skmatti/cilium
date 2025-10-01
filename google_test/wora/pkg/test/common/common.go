package common

// ClusterType represents the type of the cluster the test is running against.
type ClusterType string

const (
	ClusterTypeInfra     ClusterType = "infracluster"
	ClusterTypePerimeter ClusterType = "perimetercluster"
)
