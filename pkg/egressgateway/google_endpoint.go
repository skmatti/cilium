// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package egressgateway

import (
	"fmt"
	"net/netip"

	"github.com/cilium/cilium/pkg/time"

	"k8s.io/apimachinery/pkg/types"

	"github.com/cilium/cilium/pkg/identity"
	k8sTypes "github.com/cilium/cilium/pkg/k8s/types"
)

// endpointMetadata stores relevant metadata associated with a endpoint that's updated during endpoint
// add/update events
type googleEndpointMetadata struct {
	// identityID from where labels can be fetched from
	identityID identity.NumericIdentity

	// expirationTime is the timestamp when endpoint data will expire in the pending data store.
	expirationTime time.Time
}

type googleEndpointID struct {
	types.NamespacedName
	clusterID uint32
	ip        netip.Addr
}

func getEndpointMetadataWithoutLabels(endpoint *k8sTypes.CiliumEndpoint) (*endpointMetadata, error) {
	var addrs []netip.Addr

	id := endpointID{
		googleEndpointID: googleEndpointID{
			NamespacedName: types.NamespacedName{
				Name:      endpoint.GetName(),
				Namespace: endpoint.GetNamespace(),
			},
		},
	}

	if endpoint.UID == "" {
		// this can happen when CiliumEndpointSlices are in use - which is not supported in the EGW yet
		return nil, fmt.Errorf("endpoint has empty UID")
	}

	if endpoint.Networking == nil {
		return nil, fmt.Errorf("endpoint has no networking metadata")
	}

	if len(endpoint.Networking.Addressing) == 0 {
		return nil, fmt.Errorf("failed to get valid endpoint IPs")
	}

	for _, pair := range endpoint.Networking.Addressing {
		if pair.IPV4 != "" {
			addr, err := netip.ParseAddr(pair.IPV4)
			if err != nil || !addr.Is4() {
				continue
			}
			addrs = append(addrs, addr)
		}
	}

	// We do not support multiple IPv4 addresses per CiliumEndpoint
	if len(addrs) != 0 {
		id.ip = addrs[0]
	}

	if endpoint.Identity == nil {
		return nil, fmt.Errorf("endpoint has no identity metadata")
	}

	data := &endpointMetadata{
		ips: addrs,
		id:  id,
	}
	id.clusterID = identity.NumericIdentity(uint32(endpoint.Identity.ID)).ClusterID()

	return data, nil
}
