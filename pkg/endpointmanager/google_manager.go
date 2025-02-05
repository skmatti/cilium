package endpointmanager

import (
	"context"
	"fmt"

	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/endpoint/regeneration"
	"github.com/cilium/cilium/pkg/identity/cache"
	"github.com/cilium/cilium/pkg/ipcache"
)

type GoogleEndpointManager interface {
	CreateMultiNICHostEndpoint(ctx context.Context, owner regeneration.Owner, policyGetter policyRepoGetter, ipcache *ipcache.IPCache, proxy endpoint.EndpointProxy, allocator cache.IdentityAllocator, reason, nodeNetwork, parentDevName string) (*endpoint.Endpoint, error)
	GetMultiNICHostEndpoint(nodeNetwork string) *endpoint.Endpoint
	GetMultiNICHostEndpoints() []*endpoint.Endpoint
	InitEndpointWithNodeLabels(ctx context.Context, ep *endpoint.Endpoint)
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

// UpdateIDReferences is a wrapper on the existing updateIDReferenceLocked
// that can be useful for unit testing purposes.
func (mgr *endpointManager) UpdateIDReferences(ep *endpoint.Endpoint) {
	mgr.updateIDReferenceLocked(ep)
}

// GetMultiNICHostEndpoint returns the multi nic host endpoint for a given
// node network.
func (mgr *endpointManager) GetMultiNICHostEndpoint(nodeNetwork string) *endpoint.Endpoint {
	for _, ep := range mgr.GetMultiNICHostEndpoints() {
		if ep.GetNodeNetworkName() == nodeNetwork {
			return ep
		}
	}
	return nil
}

// GetMultiNICHostEndpoints returns all multi nic host endpoints excluding
// the default host endpoint.
func (mgr *endpointManager) GetMultiNICHostEndpoints() []*endpoint.Endpoint {
	mgr.mutex.RLock()
	defer mgr.mutex.RUnlock()
	var eps []*endpoint.Endpoint
	for _, ep := range mgr.endpoints {
		if ep.IsMultiNICHost() {
			eps = append(eps, ep)
		}
	}
	return eps
}

// InitEndpointWithNodeLabels initializes the host endpoint labels with
// the node's known labels.
func (mgr *endpointManager) InitEndpointWithNodeLabels(ctx context.Context, ep *endpoint.Endpoint) {
	mgr.initHostEndpointLabels(ctx, ep)
}

// CreateMultiNICHostEndpoint adds a multi nic host endpoint for
// a given node network.
func (mgr *endpointManager) CreateMultiNICHostEndpoint(
	ctx context.Context,
	owner regeneration.Owner,
	policyGetter policyRepoGetter,
	ipcache *ipcache.IPCache,
	proxy endpoint.EndpointProxy,
	allocator cache.IdentityAllocator,
	reason, nodeNetwork, parentDevName string,
) (*endpoint.Endpoint, error) {
	ep, err := endpoint.CreateHostEndpoint(owner, policyGetter, ipcache, proxy, allocator)
	if err != nil {
		return nil, err
	}
	ep.SetNodeNetworkName(nodeNetwork)
	ep.SetParentDevName(parentDevName)

	if err := mgr.AddEndpoint(owner, ep); err != nil {
		return nil, err
	}

	mgr.initHostEndpointLabels(ctx, ep)
	return ep, nil
}

// SetEnableGoogleMultiNIC allows to control the setting of `enable-google-multi-nic` config.
// Should be used only for tests.
func (mgr *endpointManager) SetEnableGoogleMultiNIC(googleMultiNICEnabled bool) {
	mgr.googleMultiNICEnabled = googleMultiNICEnabled
}
