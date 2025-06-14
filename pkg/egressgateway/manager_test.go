// SPDX-License-Identifier: Apache-2.0
// Authors of Cilium

package egressgateway

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/cilium/ebpf/rlimit"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/types"

	"github.com/cilium/cilium/pkg/identity"
	cilium_api_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	k8sTypes "github.com/cilium/cilium/pkg/k8s/types"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/maps/egressmap"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/testutils"
	"github.com/cilium/hive/hivetest"
)

func TestRunPendingIdentityResolverThread(t *testing.T) {
	testutils.PrivilegedTest(t)
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Log(err)
	}

	tests := []struct {
		name          string
		annotations   map[string]string
		epData        *endpointMetadata
		wantTimeout   bool
		epInDataStore bool
	}{
		{
			name: "success",
			epData: newEndpointMetadata(
				types.NamespacedName{
					Namespace: "default",
					Name:      "foo",
				},
				"10.0.0.1",
				1000,
				true,
			),
			epInDataStore: true,
		},
		{
			name: "empty_pending_entries",
		},
		{
			name: "missing_identity",
			epData: newEndpointMetadata(
				types.NamespacedName{
					Namespace: "default",
					Name:      "foo",
				},
				"10.0.0.1",
				999,
				false,
			),
			wantTimeout:   true,
			epInDataStore: false,
		},
	}
	for _, tt := range tests {
		// Create a copy of 'tt' for each iteration
		tt := tt

		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			lc := hivetest.Lifecycle(t)
			policyMap := egressmap.CreatePrivatePolicyMap(lc, egressmap.DefaultPolicyConfig)

			manager, _ := newEgressGatewayManager(Params{
				Lifecycle:         lc,
				Config:            Config{1 * time.Millisecond},
				DaemonConfig:      &option.DaemonConfig{ConfigPatchMutex: new(lock.RWMutex)},
				IdentityAllocator: identityAllocator,
				PolicyMap:         policyMap,
				Policies:          make(fakeResource[*Policy]),
				Nodes:             make(fakeResource[*cilium_api_v2.CiliumNode]),
				Endpoints:         make(fakeResource[*k8sTypes.CiliumEndpoint]),
			})
			if manager == nil {
				t.Fatal("egressGatewayManager is nil")
			}
			if tt.epData != nil {
				manager.pendingEPDataStore[tt.epData.id] = tt.epData
			}
			manager.runPendingIdentityResolverThread(context.Background())

			// Wait for the resolver thread to run and resolve the pending identity.
			// We give it a maximum of 1 second to complete.
			timeout := time.After(1200 * time.Millisecond)
			ticker := time.NewTicker(100 * time.Millisecond)
			defer ticker.Stop()

			for {
				select {
				case <-timeout:
					if tt.wantTimeout {
						return
					}
					t.Fatal("Pending identity resolver thread timed out")
				case <-ticker.C:
					manager.Lock()
					if len(manager.pendingEPDataStore) == 0 {
						if tt.epData != nil {
							_, ok := manager.epDataStore[tt.epData.id]
							if ok != tt.epInDataStore {
								t.Errorf("Unexpected epDataStore state for ep: %v. Should be present: %v, got: %v", tt.epData.id, tt.epInDataStore, ok)
							}
						}
						manager.Unlock()
						return
					}
					manager.Unlock()
				}
			}
		})
	}
}

func TestRunPendingIdentityResolverThread_withUnallocatedIdentities(t *testing.T) {
	testutils.PrivilegedTest(t)
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Log(err)
	}
	ep1 := newEndpointMetadata(
		types.NamespacedName{
			Namespace: "default",
			Name:      "foo",
		},
		"10.0.0.1",
		1001,
		true,
	)
	ep2NoIdentity := newEndpointMetadata(
		types.NamespacedName{
			Namespace: "default",
			Name:      "foo2",
		},
		"10.0.0.2",
		999,
		false,
	)
	ep3 := newEndpointMetadata(
		types.NamespacedName{
			Namespace: "default",
			Name:      "foo3",
		},
		"10.0.0.3",
		1003,
		true,
	)

	tests := []struct {
		name             string
		epData           []*endpointMetadata
		wantedEndpoints  int
		wantedPendingEPs int
	}{
		{
			name:             "with unallocated identities",
			epData:           []*endpointMetadata{ep1, ep2NoIdentity, ep3},
			wantedEndpoints:  2,
			wantedPendingEPs: 0,
		},
	}
	for _, tt := range tests {
		// Create a copy of 'tt' for each iteration
		tt := tt

		t.Run(tt.name, func(t *testing.T) {
			require.NoError(t, rlimit.RemoveMemlock())
			lc := hivetest.Lifecycle(t)
			policyMap := egressmap.CreatePrivatePolicyMap(lc, egressmap.DefaultPolicyConfig)

			manager, _ := newEgressGatewayManager(Params{
				Lifecycle:         lc,
				Config:            Config{1 * time.Millisecond},
				DaemonConfig:      &option.DaemonConfig{ConfigPatchMutex: new(lock.RWMutex)},
				IdentityAllocator: identityAllocator,
				PolicyMap:         policyMap,
				Policies:          make(fakeResource[*Policy]),
				Nodes:             make(fakeResource[*cilium_api_v2.CiliumNode]),
				Endpoints:         make(fakeResource[*k8sTypes.CiliumEndpoint]),
			})

			if manager == nil {
				t.Fatal("egressGatewayManager is nil")
			}

			if tt.epData != nil {
				for _, ep := range tt.epData {
					// TODO(b/402137669): Add tests for OnIPIdentityCacheChange so we can test ipcache triggered reconcile properly.
					// TODO(b/402137668): Mock time.Now() properly to fully test this functionality.
					ep.expirationTime = time.Now()
					manager.pendingEPDataStore[ep.id] = ep
				}
			}

			manager.runPendingIdentityResolverThread(context.Background())

			// Allow invalid identities to expire
			timeout := time.After(5 * time.Second)
			ticker := time.NewTicker(1 * time.Second)
			defer ticker.Stop()

			for {
				select {
				case <-timeout:
					t.Fatal("Pending identity resolver thread timed out")
				case <-ticker.C:
					manager.Lock()
					if len(manager.pendingEPDataStore) == tt.wantedPendingEPs && len(manager.epDataStore) == tt.wantedEndpoints {
						manager.Unlock()
						return
					}
					manager.Unlock()
				}
			}
		})
	}
}

func newEndpointMetadata(name types.NamespacedName, ip string, id int, allocateIdentity bool) *endpointMetadata {
	identityID := identity.NumericIdentity(id)
	if allocateIdentity {
		id, _, _ := identityAllocator.AllocateIdentity(context.Background(), labels.Map2Labels(ep1Labels, labels.LabelSourceK8s), true, identity.InvalidIdentity)
		identityID = id.ID
	}
	epData := &endpointMetadata{
		ips: []netip.Addr{netip.MustParseAddr(ip)},
		id: endpointID{
			googleEndpointID: googleEndpointID{
				NamespacedName: name,
				clusterID:      1,
			},
		},
		googleEndpointMetadata: googleEndpointMetadata{
			identityID: identityID,
		},
	}
	return epData
}
