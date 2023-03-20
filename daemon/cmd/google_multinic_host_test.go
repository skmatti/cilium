package cmd

import (
	"context"
	"sort"
	"strings"
	"testing"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/ipcache"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/watchers"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/google/go-cmp/cmp"
)

func TestEnsureMultiNICHostEndpoint(t *testing.T) {
	option.Config.EnableGoogleMultiNICHostFirewall = true
	defer func() {
		option.Config.EnableGoogleMultiNICHostFirewall = false
	}()
	testID := identity.NumericIdentity(140)
	testNodeNetwork := "test-node-network1"

	idSet := map[string]string{
		testID.String(): testNodeNetwork,
	}
	if err := identity.InitMultiNICHostNumericIdentitySet(idSet); err != nil {
		t.Fatalf("identity.InitMultiNICHostNumericIdentitySet(%v) = %v, want nil", idSet, err)
	}
	defer func() {
		identity.DeleteReservedIdentity(testID)
	}()

	tests := []struct {
		desc string
		// precreates the endpoint to test updates.
		precreate bool
		// Restored endpoints but not populated in endpoint manager yet.
		restored []*endpoint.Endpoint
		network  string
		dev      string
		wantEP   *endpoint.Endpoint
	}{
		{
			desc:    "default network",
			network: identity.DefaultMultiNICNodeNetwork,
			dev:     "dev1",
		},
		{
			desc:    "node network without reserved identity",
			network: "other-network",
			dev:     "dev1",
		},
		{
			desc:      "initialize multi nic host labels",
			precreate: true,
			network:   testNodeNetwork,
			dev:       "dev2",
			wantEP: func() *endpoint.Endpoint {
				ep := &endpoint.Endpoint{}
				ep.SetNodeNetworkName(testNodeNetwork)
				ep.SetParentDevName("dev2")
				ep.SetIsHost(true)
				lbls := labels.NewReservedMultiNICHostLabels(testNodeNetwork)
				lbls.MergeLabels(labels.LabelHost)
				ep.OpLabels = labels.OpLabels{
					OrchestrationIdentity: lbls,
				}
				return ep
			}(),
		},
	}

	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			d := newTestDaemon()
			if tc.precreate {
				ep, _, err := d.createEndpoint(d.ctx, d, &models.EndpointChangeRequest{})
				if err != nil {
					t.Fatalf("createEndpoint() = %v, want nil", err)
				}
				ep.SetNodeNetworkName(testNodeNetwork)
				ep.SetParentDevName(tc.dev)
				ep.SetIsHost(true)
				d.endpointManager.UpdateIDReferences(ep)
			}

			got, err := d.EnsureMultiNICHostEndpoint(tc.restored, tc.network, tc.dev)
			if err != nil {
				t.Fatalf("EnsureMultiNICHostEndpoint(_, %s, %s) = %v, want nil", tc.network, tc.dev, err)
			}
			if tc.wantEP == nil {
				if got != nil {
					t.Errorf("EnsureMultiNICHostEndpoint(_, %s, %s) = %+v, want nil", tc.network, tc.dev, got)
				}
				return
			}
			// Validate that multinic device is cached.
			if !node.IsMultiNICHostDevice(tc.dev) {
				t.Errorf("IsMultiNICHostDevice(%s) = false, want true", tc.dev)
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
			wantLbls := tc.wantEP.OpLabels.AllLabels()
			gotLbls := got.OpLabels.AllLabels()
			if diff := cmp.Diff(wantLbls, gotLbls); diff != "" {
				t.Errorf("Unexpected endpoint labels diff (-want +got):\n%s", diff)
			}
		})
	}
}

func TestEnsureMultiNICHostEndpoint_Errors(t *testing.T) {
	option.Config.EnableGoogleMultiNICHostFirewall = true
	defer func() {
		option.Config.EnableGoogleMultiNICHostFirewall = false
	}()
	testID := identity.NumericIdentity(140)
	testNodeNetwork := "test-node-network1"
	testParentDevice := "device-" + testNodeNetwork

	idSet := map[string]string{
		testID.String(): testNodeNetwork,
	}
	if err := identity.InitMultiNICHostNumericIdentitySet(idSet); err != nil {
		t.Fatalf("identity.InitMultiNICHostNumericIdentitySet(%v) = %v, want nil", idSet, err)
	}
	defer func() {
		identity.DeleteReservedIdentity(testID)
	}()

	tests := []struct {
		desc       string
		restored   []*endpoint.Endpoint
		network    string
		dev        string
		wantErrMsg string
	}{
		{
			desc: "multi nic host endpoint not restored yet",
			restored: []*endpoint.Endpoint{
				func() *endpoint.Endpoint {
					ep := &endpoint.Endpoint{}
					ep.SetNodeNetworkName(testNodeNetwork)
					ep.SetParentDevName("dev1")
					ep.SetIsHost(true)
					return ep
				}(),
			},
			network:    testNodeNetwork,
			dev:        testParentDevice,
			wantErrMsg: "wait for multi nic host endpoint for node network",
		},
	}

	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			d := newTestDaemon()
			_, err := d.EnsureMultiNICHostEndpoint(tc.restored, tc.network, tc.dev)
			if (err != nil && tc.wantErrMsg == "") ||
				(tc.wantErrMsg != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErrMsg))) {
				t.Fatalf("EnsureMultiNICHostEndpoint(_, %s, %s) = %v, want %s", tc.network, tc.dev, err, tc.wantErrMsg)
			}
		})
	}
}

func TestDeleteMultiNICHostEndpoint(t *testing.T) {
	currDryRunMode := option.Config.DryMode
	option.Config.EnableGoogleMultiNICHostFirewall = true
	// Enable dry run mode to skip bpf cleanup.
	option.Config.DryMode = true
	defer func() {
		option.Config.EnableGoogleMultiNICHostFirewall = false
		option.Config.DryMode = currDryRunMode
	}()
	testNodeNetwork := "test-node-network1"

	tests := []struct {
		desc string
		// a slice of existing networks
		existingNetworks []string
		network          string
		wantNetworks     []string
	}{
		{
			desc:             "default host endpoint not deleted",
			existingNetworks: []string{identity.DefaultMultiNICNodeNetwork},
			network:          identity.DefaultMultiNICNodeNetwork,
			wantNetworks:     []string{identity.DefaultMultiNICNodeNetwork},
		},
		{
			desc:             "delete multi nic host endpoint",
			existingNetworks: []string{identity.DefaultMultiNICNodeNetwork, testNodeNetwork},
			network:          testNodeNetwork,
			wantNetworks:     []string{identity.DefaultMultiNICNodeNetwork},
		},
		{
			desc:             "non existing multi nic host endpoint",
			existingNetworks: []string{identity.DefaultMultiNICNodeNetwork, testNodeNetwork},
			network:          "other-network",
			wantNetworks:     []string{identity.DefaultMultiNICNodeNetwork, testNodeNetwork},
		},
	}

	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			d := newTestDaemon()
			for _, network := range tc.existingNetworks {
				ep, _, err := d.createEndpoint(context.Background(), d, &models.EndpointChangeRequest{})
				if err != nil {
					t.Fatalf("createEndpoint() = %v, want nil", err)
				}
				device := "dev-" + network
				ep.SetNodeNetworkName(network)
				ep.SetParentDevName(device)
				ep.SetIsHost(true)
				if ep.IsMultiNICHost() {
					node.AddMultiNICHostDevice(device)
				}
				d.endpointManager.UpdateIDReferences(ep)
			}

			device := "dev-" + tc.network
			err := d.DeleteMultiNICHostEndpoint(tc.network, device)
			if err != nil {
				t.Fatalf("DeleteMultiNICHostEndpoint(%s) = %v, want nil", tc.network, err)
			}

			if node.IsMultiNICHostDevice(device) {
				t.Errorf("IsMultiNICHostDevice(%s) = true, want false", device)
			}

			allHostEps := d.endpointManager.GetMultiNICHostEndpoints()
			allHostEps = append(allHostEps, d.endpointManager.GetHostEndpoint())
			var allHostNetworks []string
			for _, ep := range allHostEps {
				allHostNetworks = append(allHostNetworks, ep.GetNodeNetworkName())
			}
			sort.Strings(allHostNetworks)

			if diff := cmp.Diff(tc.wantNetworks, allHostNetworks); diff != "" {
				t.Errorf("Unexpected node networks diff (-want +got):\n%s", diff)
			}
		})
	}
}

func newTestDaemon() *Daemon {
	client, _ := k8sClient.NewFakeClientset()
	d := &Daemon{
		ctx: context.Background(),
		endpointManager: WithCustomEndpointManager(
			&watchers.EndpointSynchronizer{
				Clientset: client,
			},
		),
		ipcache: &ipcache.IPCache{},
		policy:  policy.NewPolicyRepository(nil, nil, nil),
	}
	d.identityAllocator = NewCachingIdentityAllocator(d)
	return d
}
