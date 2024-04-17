package xds

const (
	// URL for each discovery service. Used as key for resource type as well.

	// LDS service URL
	LDS = "type.googleapis.com/envoy.config.listener.v3.Listener"
	// RDS service URL
	RDS = "type.googleapis.com/envoy.config.route.v3.RouteConfiguration"
	// CDS service URL
	CDS = "type.googleapis.com/envoy.config.cluster.v3.Cluster"
	// EDS service URL
	EDS = "type.googleapis.com/envoy.config.endpoint.v3.ClusterLoadAssignment"
	// FIT type URL
	FIT = "type.googleapis.com/envoy.extensions.filters.network.fault.v1.TransportFault"
)
