package endpointmanager

import (
	"fmt"

	"github.com/cilium/cilium/pkg/endpoint"
	endpointid "github.com/cilium/cilium/pkg/endpoint/id"
	"github.com/cilium/cilium/pkg/option"
)

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
func (mgr *EndpointManager) LookupEndpointsByContainerID(id string) []*endpoint.Endpoint {
	mgr.mutex.RLock()
	eps := mgr.endpointsMultiNIC[endpointid.NewID(endpointid.ContainerIdPrefix, id)]
	mgr.mutex.RUnlock()
	return eps
}

// LookupEndpointsByPodName looks up all endpoints in a pod by namespace + pod name.
// Only call if EnableGoogleMultiNIC is true.
// May return nil or zero length slice if not found.
func (mgr *EndpointManager) LookupEndpointsByPodName(name string) []*endpoint.Endpoint {
	mgr.mutex.RLock()
	eps := mgr.endpointsMultiNIC[endpointid.NewID(endpointid.PodNamePrefix, name)]
	mgr.mutex.RUnlock()
	return eps
}

// LookupPrimaryEndpointByContainerID looks up the primary (veth) endpoint in a container.
func (mgr *EndpointManager) LookupPrimaryEndpointByContainerID(id string) *endpoint.Endpoint {
	mgr.mutex.RLock()
	defer mgr.mutex.RUnlock()
	if !option.Config.EnableGoogleMultiNIC {
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
func (mgr *EndpointManager) LookupPrimaryEndpointByPodName(name string) *endpoint.Endpoint {
	mgr.mutex.RLock()
	defer mgr.mutex.RUnlock()
	if !option.Config.EnableGoogleMultiNIC {
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

func (mgr *EndpointManager) addToMultiNICMapIfNeeded(ep *endpoint.Endpoint, prefix endpointid.PrefixType, id string) bool {
	if option.Config.EnableGoogleMultiNIC && (prefix == endpointid.ContainerIdPrefix || prefix == endpointid.PodNamePrefix || prefix == endpointid.DockerEndpointPrefix || prefix == endpointid.ContainerNamePrefix) {
		mgr.endpointsMultiNIC[id] = append(mgr.endpointsMultiNIC[id], ep)
		return true
	}
	return false
}

func (mgr *EndpointManager) removeFromMultiNICMapIfNeeded(ep *endpoint.Endpoint, prefix endpointid.PrefixType, id string) {
	if option.Config.EnableGoogleMultiNIC && (prefix == endpointid.ContainerIdPrefix || prefix == endpointid.PodNamePrefix || prefix == endpointid.DockerEndpointPrefix || prefix == endpointid.ContainerNamePrefix) {
		eps := mgr.endpointsMultiNIC[id]
		if len(eps) == 0 {
			return
		}
		for i, epInList := range eps {
			if ep.ID == epInList.ID {
				// Remove the endpoint at index.
				eps[i] = eps[len(eps)-1]
				mgr.endpointsMultiNIC[id] = eps[:len(eps)-1]
			}
		}
	}
}
