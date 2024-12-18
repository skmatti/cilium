package endpointmanager

import (
	"fmt"

	"github.com/cilium/cilium/pkg/endpoint"
	endpointid "github.com/cilium/cilium/pkg/endpoint/id"
	"github.com/cilium/cilium/pkg/gke/features"
)

type GoogleEndpointManager interface {
	LookupEndpointsByContainerID(id string) []*endpoint.Endpoint
	LookupEndpointsByPodName(name string) []*endpoint.Endpoint
	LookupPrimaryEndpointByContainerID(id string) *endpoint.Endpoint
	LookupPrimaryEndpointByPodName(name string) *endpoint.Endpoint
}

// ErrUnsupportedWhenMultiNIC represents the error of an unsupported Lookup when multi-nic is enabled.
type ErrUnsupportedWhenMultiNIC struct {
	// Prefix contains the prefix.
	Prefix string
}

// Error returns the string representation of the ErrUnsupportedWhenMultiNIC.
func (e ErrUnsupportedWhenMultiNIC) Error() string {
	return fmt.Sprintf("can't call EndpointManager::Lookup with %q when EnableGoogleMultiNIC is true", e.Prefix)
}

// LookupEndpointsByContainerID looks up all endpoints in a container.
// Only call if EnableGoogleMultiNIC is true.
// May return nil or zero length slice if not found.
func (mgr *endpointManager) LookupEndpointsByContainerID(id string) []*endpoint.Endpoint {
	mgr.mutex.RLock()
	eps := mgr.endpointsMultiNIC[endpointid.NewID(endpointid.ContainerIdPrefix, id)]
	mgr.mutex.RUnlock()
	return eps
}

// LookupEndpointsByPodName looks up all endpoints in a pod by namespace + pod name.
// Only call if EnableGoogleMultiNIC is true.
// May return nil or zero length slice if not found.
func (mgr *endpointManager) LookupEndpointsByPodName(name string) []*endpoint.Endpoint {
	mgr.mutex.RLock()
	eps := mgr.endpointsMultiNIC[endpointid.NewID(endpointid.PodNamePrefix, name)]
	mgr.mutex.RUnlock()
	return eps
}

// LookupPrimaryEndpointByContainerID looks up the primary (veth) endpoint in a container.
func (mgr *endpointManager) LookupPrimaryEndpointByContainerID(id string) *endpoint.Endpoint {
	mgr.mutex.RLock()
	defer mgr.mutex.RUnlock()
	if !features.GlobalConfig.EnableGoogleMultiNIC {
		return mgr.lookupContainerID(id)
	}

	eps := mgr.endpointsMultiNIC[endpointid.NewID(endpointid.ContainerIdPrefix, id)]
	for _, ep := range eps {
		if !ep.IsMultiNIC() {
			return ep
		}
	}
	return nil
}

// LookupPrimaryEndpointByPodName looks up the primary (veth) endpoint of a pod by namespace + pod name.
func (mgr *endpointManager) LookupPrimaryEndpointByPodName(name string) *endpoint.Endpoint {
	mgr.mutex.RLock()
	defer mgr.mutex.RUnlock()
	if !features.GlobalConfig.EnableGoogleMultiNIC {
		return mgr.lookupPodNameLocked(name)
	}

	eps := mgr.endpointsMultiNIC[endpointid.NewID(endpointid.PodNamePrefix, name)]
	for _, ep := range eps {
		if !ep.IsMultiNIC() {
			return ep
		}
	}
	return nil
}

// UpdateIDReferences is a wrapper on the existing updateIDReferenceLocked
// that can be useful for unit testing purposes.
func (mgr *endpointManager) UpdateIDReferences(ep *endpoint.Endpoint) {
	mgr.updateIDReferenceLocked(ep)
}

func (mgr *endpointManager) addToMultiNICMapIfNeeded(ep *endpoint.Endpoint, prefix endpointid.PrefixType, id string) bool {
	if features.GlobalConfig.EnableGoogleMultiNIC && (prefix == endpointid.ContainerIdPrefix || prefix == endpointid.PodNamePrefix || prefix == endpointid.DockerEndpointPrefix || prefix == endpointid.ContainerNamePrefix) {
		mgr.endpointsMultiNIC[id] = append(mgr.endpointsMultiNIC[id], ep)
		return true
	}
	return false
}

func (mgr *endpointManager) removeFromMultiNICMapIfNeeded(ep *endpoint.Endpoint, prefix endpointid.PrefixType, id string) {
	if features.GlobalConfig.EnableGoogleMultiNIC && (prefix == endpointid.ContainerIdPrefix || prefix == endpointid.PodNamePrefix || prefix == endpointid.DockerEndpointPrefix || prefix == endpointid.ContainerNamePrefix) {
		eps := mgr.endpointsMultiNIC[id]
		for i := len(eps) - 1; i >= 0; i-- {
			if eps[i].ID == ep.ID {
				eps = append(eps[:i], eps[i+1:]...)
			}
		}
		if len(eps) == 0 {
			delete(mgr.endpointsMultiNIC, id)
			return
		}
		mgr.endpointsMultiNIC[id] = eps
	}
}
