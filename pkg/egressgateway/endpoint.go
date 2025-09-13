// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package egressgateway

import (
	"net/netip"

	"k8s.io/apimachinery/pkg/types"

	k8sTypes "github.com/cilium/cilium/pkg/k8s/types"
	"github.com/cilium/cilium/pkg/labels"
)

// endpointMetadata stores relevant metadata associated with a endpoint that's updated during endpoint
// add/update events
type endpointMetadata struct {
	// Endpoint labels
	labels map[string]string
	// Endpoint ID
	id endpointID
	// ips are endpoint's unique IPs
	ips []netip.Addr

	googleEndpointMetadata
}

// endpointID is based on endpoint's UID and cluster ID
type endpointID struct {
	UID types.UID

	googleEndpointID
}

func getEndpointMetadata(endpoint *k8sTypes.CiliumEndpoint, identityLabels labels.Labels) (*endpointMetadata, error) {
	data, err := getEndpointMetadataWithoutLabels(endpoint)
	if err != nil {
		return nil, err
	}
	data.labels = identityLabels.K8sStringMap()

	return data, nil
}
