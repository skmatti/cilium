package controller

import (
	"strings"
	"testing"

	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
)

var testLog = logging.DefaultLogger.WithField(logfields.LogSubsys, "test")

type fakeEpMgrImpl struct {
	endpoints []*endpoint.Endpoint
}

func (fem *fakeEpMgrImpl) Subscribe(endpointmanager.Subscriber) {}

func (fem *fakeEpMgrImpl) GetEndpoints() []*endpoint.Endpoint {
	return fem.endpoints
}

func (fem *fakeEpMgrImpl) GetHostEndpoint() *endpoint.Endpoint {
	for _, ep := range fem.endpoints {
		if ep.IsDefaultHost() {
			return ep
		}
	}
	return nil
}

func (fem *fakeEpMgrImpl) EnsureMultiNICHostEndpoint(_ []*endpoint.Endpoint, network, parentDevice string) (*endpoint.Endpoint, error) {
	if !option.Config.EnableGoogleMultiNICHostFirewall || network == identity.DefaultMultiNICNodeNetwork {
		return nil, nil
	}
	ep := newTestEndpoint(network, parentDevice, true)
	fem.endpoints = append(fem.endpoints, ep)
	return ep, nil
}

func (fem *fakeEpMgrImpl) DeleteMultiNICHostEndpoint(network, parentDevice string) error { return nil }

func TestCreateHostEndpointIfNeeded(t *testing.T) {
	oldDevices := option.Config.GetDevices()
	option.Config.SetDevices([]string{"dev2"})
	defer func() {
		option.Config.SetDevices(oldDevices)
	}()
	tests := []struct {
		desc                    string
		disableMultiNICFirewall bool
		endpoints               []*endpoint.Endpoint
		network                 string
		dev                     string
		wantEP                  *endpoint.Endpoint
	}{
		{
			desc:                    "disable multi nic host firewall returns default host",
			disableMultiNICFirewall: true,
			endpoints: []*endpoint.Endpoint{
				newTestEndpoint("" /*network*/, "dev1", true /*isHost*/),
				newTestEndpoint("node-network1", "dev2", true),
			},
			network: "node-network1",
			dev:     "dev1",
			wantEP:  newTestEndpoint("", "dev1", true),
		},
		{
			desc:                    "cilium managed device returns nil",
			disableMultiNICFirewall: true,
			endpoints: []*endpoint.Endpoint{
				newTestEndpoint("" /*network*/, "dev1", true /*isHost*/),
				newTestEndpoint("node-network2", "dev2", true),
			},
			network: "node-network2",
			dev:     "dev2",
		},
		{
			desc: "cilium managed device returns multi nic host",
			endpoints: []*endpoint.Endpoint{
				newTestEndpoint("" /*network*/, "dev1", true /*isHost*/),
				newTestEndpoint("node-network2", "dev2", true),
			},
			network: "node-network2",
			dev:     "dev2",
			wantEP:  newTestEndpoint("node-network2", "dev2", true),
		},
		{
			desc: "default network returns default host",
			endpoints: []*endpoint.Endpoint{
				newTestEndpoint("" /*network*/, "dev1", true /*isHost*/),
				newTestEndpoint("node-network2", "dev2", true),
			},
			network: identity.DefaultMultiNICNodeNetwork,
			dev:     "dev3",
			wantEP:  newTestEndpoint("", "dev1", true),
		},
		{
			desc: "return existing multi nic host",
			endpoints: []*endpoint.Endpoint{
				newTestEndpoint("" /*network*/, "dev1", true /*isHost*/),
				newTestEndpoint("node-network3", "dev3", true),
			},
			network: "node-network3",
			dev:     "dev3",
			wantEP:  newTestEndpoint("node-network3", "dev3", true),
		},
		{
			desc: "create multi nic host",
			endpoints: []*endpoint.Endpoint{
				newTestEndpoint("" /*network*/, "dev1", true /*isHost*/),
				newTestEndpoint("node-network2", "dev2", true),
			},
			network: "node-network4",
			dev:     "dev4",
			wantEP:  newTestEndpoint("node-network4", "dev4", true),
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.desc, func(t *testing.T) {
			if !tc.disableMultiNICFirewall {
				option.Config.EnableGoogleMultiNICHostFirewall = true
				defer func() {
					option.Config.EnableGoogleMultiNICHostFirewall = false
				}()
			}
			epManager := &fakeEpMgrImpl{endpoints: tc.endpoints}
			testReconciler := &NetworkReconciler{
				EndpointManager:     epManager,
				HostEndpointManager: epManager,
				Log:                 testLog,
			}
			got, err := testReconciler.createHostEndpointIfNeeded(tc.network, tc.dev)
			if err != nil {
				t.Fatalf("createHostEndpointIfNeeded(_, %s, %s) = %v, want nil", tc.network, tc.dev, err)
			}
			if tc.wantEP == nil {
				if got != nil {
					t.Fatalf("createHostEndpointIfNeeded(_, %s, %s) = %+v, want nil", tc.network, tc.dev, got)
				}
				return
			}
			if tc.wantEP.GetNodeNetworkName() != got.GetNodeNetworkName() {
				t.Errorf("ep.GetNodeNetworkName() = %s, want %s", got.GetNodeNetworkName(), tc.wantEP.GetNodeNetworkName())
			}
			if tc.wantEP.GetParentDevName() != got.GetParentDevName() {
				t.Errorf("ep.GetParentDevName() = %s, want %s", got.GetParentDevName(), tc.wantEP.GetParentDevName())
			}
			if tc.wantEP.IsHost() != got.IsHost() {
				t.Errorf("ep.IsHost() = %t, want %t", got.IsHost(), tc.wantEP.IsHost())
			}
		})
	}
}

func TestCreateHostEndpointIfNeeded_Errors(t *testing.T) {
	oldDevices := option.Config.GetDevices()
	option.Config.SetDevices([]string{"dev2"})
	defer func() {
		option.Config.SetDevices(oldDevices)
	}()
	tests := []struct {
		desc                    string
		disableMultiNICFirewall bool
		endpoints               []*endpoint.Endpoint
		network                 string
		dev                     string
		wantErrMsg              string
	}{
		{
			desc: "missing host endpoint returns error",
			endpoints: []*endpoint.Endpoint{
				newTestEndpoint("node-network1", "dev1", true),
			},
			network:    "node-network1",
			dev:        "dev1",
			wantErrMsg: "host endpoint not found",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.desc, func(t *testing.T) {
			if !tc.disableMultiNICFirewall {
				option.Config.EnableGoogleMultiNICHostFirewall = true
				defer func() {
					option.Config.EnableGoogleMultiNICHostFirewall = false
				}()
			}
			epManager := &fakeEpMgrImpl{endpoints: tc.endpoints}
			testReconciler := &NetworkReconciler{
				EndpointManager:     epManager,
				HostEndpointManager: epManager,
				Log:                 testLog,
			}
			_, err := testReconciler.createHostEndpointIfNeeded(tc.network, tc.dev)
			if (err != nil && tc.wantErrMsg == "") ||
				(tc.wantErrMsg != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErrMsg))) {
				t.Fatalf("createHostEndpointIfNeeded(_, %s, %s) = %v, want %s", tc.network, tc.dev, err, tc.wantErrMsg)
			}
		})
	}
}

func newTestEndpoint(network, dev string, isHost bool) *endpoint.Endpoint {
	option.Config.EnableGoogleMultiNICHostFirewall = true
	defer func() {
		option.Config.EnableGoogleMultiNICHostFirewall = false
	}()
	ep := &endpoint.Endpoint{}
	ep.SetNodeNetworkName(network)
	ep.SetParentDevName(dev)
	ep.SetIsHost(isHost)
	return ep
}
