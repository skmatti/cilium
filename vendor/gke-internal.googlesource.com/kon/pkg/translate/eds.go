package translate

import (
	"fmt"
	"strings"

	corepb "github.com/cilium/proxy/go/envoy/config/core/v3"
	endpointpb "github.com/cilium/proxy/go/envoy/config/endpoint/v3"
	"gke-internal.googlesource.com/kon/pkg/model"
)

var healthyStatuses = map[corepb.HealthStatus]bool{
	corepb.HealthStatus_HEALTHY: true,
	corepb.HealthStatus_UNKNOWN: true,
}

// ParseCLA parses the given CLA to a subset of the endpoint
func ParseCLA(cla *endpointpb.ClusterLoadAssignment) *model.EndpointSubset {
	if cla == nil {
		return nil
	}
	s := &model.EndpointSubset{
		XDSCluster: cla.GetClusterName(),
	}
	for _, ep := range cla.Endpoints {
		endpoints := parseLocalityLBEndpoints(ep)
		s.Endpoints = append(s.Endpoints, endpoints...)
	}
	return s
}

func parseLocalityLBEndpoints(llep *endpointpb.LocalityLbEndpoints) (endpoints []model.Endpoint) {
	sz := llep.GetLocality().GetSubZone()
	zone, err := parseZone(sz)
	if err != nil {
		Log.Warningf("Failed to parse zone for %s: %v", sz, err)
	}
	for _, lep := range llep.GetLbEndpoints() {
		var endpoint model.Endpoint
		ep := lep.GetEndpoint()
		if ep == nil {
			Log.Warningf("Unexpected nil endpoint in LBEndpoint for %s", sz)
			continue
		}
		address := ep.GetAddress()
		if address == nil {
			Log.Warningf("Unexpected nil address in LBEndpoint for %s", sz)
			continue
		}
		socketAddress := address.GetSocketAddress()
		if socketAddress == nil {
			Log.Warningf("Unexpected non SocketAddress in LBEndpoint Address for %s", sz)
			continue
		}
		// endpoint is ready when its health status is HEALTHY.
		health := lep.GetHealthStatus()
		endpoint.Ready = healthyStatuses[health]
		endpoint.Address.IP = socketAddress.GetAddress()
		endpoint.Address.Port = socketAddress.GetPortValue()
		endpoint.Address.Zone = zone
		endpoints = append(endpoints, endpoint)
	}
	return endpoints
}

// Parse xds locality value to zone.
// The sub-zone has the format as "jq:us-central1-c_6770876014261648616_neg"
func parseZone(subzone string) (string, error) {
	if subzone == "__blackhole__" {
		return subzone, nil
	}
	tokens := strings.FieldsFunc(subzone, func(r rune) bool {
		return r == ':' || r == '_'
	})
	if len(tokens) != 4 {
		return "", fmt.Errorf("unexpected format of %s", subzone)
	}
	return tokens[1], nil
}
