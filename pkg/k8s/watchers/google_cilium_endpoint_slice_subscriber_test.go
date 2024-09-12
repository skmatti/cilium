// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium
package watchers

import (
	"net"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"github.com/cilium/cilium/pkg/k8s"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"

	"github.com/cilium/cilium/pkg/k8s/types"
)

var (
	ipv4Addr    = net.ParseIP("1.1.1.1")
	ipv6Addr1_1 = net.ParseIP("1::1")
	ipv6Addr2_2 = net.ParseIP("2::2")
)

// WithMultiNetworking returns a coroutines which:
//   - adds the IP address to the networking addresses, then;
//   - updates the CEP name.
//
// Note: this appends the address to the pair list; if an address is already present,
// the addess specified to this function will not be used for the CEP naming.
func WithMultiNetworking(ip net.IP) func(*types.CiliumEndpoint) {
	return func(e *types.CiliumEndpoint) {
		if e.Networking == nil {
			e.Networking = &v2.EndpointNetworking{}
		}
		pair := &v2.AddressPair{}
		if v4 := ip.To4(); v4 != nil {
			pair.IPV4 = v4.String()
		} else if v6 := ip.To16(); v6 != nil {
			pair.IPV6 = v6.String()
		}

		e.Networking.Addressing = append(e.Networking.Addressing, pair)
		e.Name = k8s.CEPKey(e, "").Name
	}
}

// WithID returns a coroutine which sets the identity on an endpoint.
func WithID(id int64) func(*types.CiliumEndpoint) {
	return func(e *types.CiliumEndpoint) {
		if e.Identity == nil {
			e.Identity = &v2.EndpointIdentity{}
		}
		e.Identity.ID = id
	}
}

func newCiliumEndpoint(name, namespace string, opts ...func(*types.CiliumEndpoint)) *types.CiliumEndpoint {
	e := &types.CiliumEndpoint{
		ObjectMeta: slim_metav1.ObjectMeta{
			Namespace: namespace,
			Name:      name,
			OwnerReferences: []slim_metav1.OwnerReference{
				{
					Kind: "Pod",
					Name: name,
				},
			},
		},
		Identity:   &v2.EndpointIdentity{ID: 0},
		Encryption: &v2.EncryptionSpec{},
	}
	for _, opt := range opts {
		opt(e)
	}

	return e
}

func TestCESSubscriber_MultiNetwork_OnAdd(t *testing.T) {
	testCases := []struct {
		name       string
		local      []cacheEntry
		ces        *v2alpha1.CiliumEndpointSlice
		expectAdds []endpointUpdate
		// Expected cepToCESmap.expectedCurrentCES
		expectedCurrentCES map[string]string
	}{
		{
			name: "one_cep",
			ces: newCES("ces", testNamespace,
				v2alpha1.CoreCiliumEndpoint{
					Name: "cep",
					Networking: &v2.EndpointNetworking{
						Addressing: v2.AddressPairList{
							{IPV4: ipv4Addr.String()},
						},
					},
				},
			),
			expectAdds: []endpointUpdate{
				{NewEP: newCiliumEndpoint("cep", testNamespace, WithMultiNetworking(ipv4Addr))},
			},
			expectedCurrentCES: map[string]string{
				"default/cep1-1-1-1": "ces",
			},
		},
		{
			name: "two_ceps",
			ces: newCES("ces", testNamespace,
				v2alpha1.CoreCiliumEndpoint{
					Name: "cep",
					Networking: &v2.EndpointNetworking{
						Addressing: v2.AddressPairList{
							{IPV4: ipv4Addr.String()},
						},
					},
				},
				v2alpha1.CoreCiliumEndpoint{
					Name: "cep",
					Networking: &v2.EndpointNetworking{
						Addressing: v2.AddressPairList{
							{IPV6: ipv6Addr1_1.String()},
						},
					},
				},
			),
			expectAdds: []endpointUpdate{
				{NewEP: newCiliumEndpoint("cep", testNamespace, WithMultiNetworking(ipv4Addr))},
				{NewEP: newCiliumEndpoint("cep", testNamespace, WithMultiNetworking(ipv6Addr1_1))},
			},
			expectedCurrentCES: map[string]string{
				"default/cep1-1-1-1": "ces",
				"default/cep1--1":    "ces",
			},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			watcher := newFakeEPWatcher()
			m := &cepToCESmap{
				cepMap:     make(map[string]cesToCEPRef),
				currentCES: make(map[string]string),
			}
			subscriber := &cesSubscriber{
				epWatcher: watcher,
				epCache:   newFakeEndpointCache(tc.local...),
				cepMap:    m,
			}

			subscriber.OnAdd(tc.ces)

			if diff := cmp.Diff(tc.expectAdds, watcher.updates, cmpopts.SortSlices(updateLess)); diff != "" {
				t.Errorf("Unexpected CEP updates(s) (-want +got):\n%s", diff)
			}

			if diff := cmp.Diff(tc.expectedCurrentCES, m.currentCES); diff != "" {
				t.Fatalf("Unexpected CEP to CES mapping (-want +got):\n%s", diff)
			}
		})
	}
}

func TestCESSubscriber_MultiNetwork_OnUpdate(t *testing.T) {
	testCases := []struct {
		name           string
		local          []cacheEntry
		newCES, oldCES *v2alpha1.CiliumEndpointSlice
		expectUpdates  []endpointUpdate
		expectDeleted  []*types.CiliumEndpoint
		// Expected cepToCESmap.expectedCurrentCES
		expectedCurrentCES map[string]string
	}{
		{
			name: "update_all",
			oldCES: newCES("ces", testNamespace,
				v2alpha1.CoreCiliumEndpoint{
					Name: "cep",
					Networking: &v2.EndpointNetworking{
						Addressing: v2.AddressPairList{
							{IPV4: ipv4Addr.String()},
						},
					},
				},
				v2alpha1.CoreCiliumEndpoint{
					Name: "cep",
					Networking: &v2.EndpointNetworking{
						Addressing: v2.AddressPairList{
							{IPV6: ipv6Addr1_1.String()},
						},
					},
				},
			),
			newCES: newCES("ces", testNamespace,
				v2alpha1.CoreCiliumEndpoint{
					Name:       "cep",
					IdentityID: 1,
					Networking: &v2.EndpointNetworking{
						Addressing: v2.AddressPairList{
							{IPV4: ipv4Addr.String()},
						},
					},
				},
				v2alpha1.CoreCiliumEndpoint{
					Name:       "cep",
					IdentityID: 1,
					Networking: &v2.EndpointNetworking{
						Addressing: v2.AddressPairList{
							{IPV6: ipv6Addr1_1.String()},
						},
					},
				},
			),
			expectUpdates: []endpointUpdate{
				{
					OldEP: newCiliumEndpoint("cep", testNamespace, WithMultiNetworking(ipv4Addr)),
					NewEP: newCiliumEndpoint("cep", testNamespace, WithID(1), WithMultiNetworking(ipv4Addr)),
				},
				{
					OldEP: newCiliumEndpoint("cep", testNamespace, WithMultiNetworking(ipv6Addr1_1)),
					NewEP: newCiliumEndpoint("cep", testNamespace, WithID(1), WithMultiNetworking(ipv6Addr1_1)),
				},
			},
			expectedCurrentCES: map[string]string{
				"default/cep1-1-1-1": "ces",
				"default/cep1--1":    "ces",
			},
		},
		{
			name: "update_cep1",
			oldCES: newCES("ces", testNamespace,
				v2alpha1.CoreCiliumEndpoint{
					Name: "cep",
					Networking: &v2.EndpointNetworking{
						Addressing: v2.AddressPairList{
							{IPV4: ipv4Addr.String()},
						},
					},
				},
				v2alpha1.CoreCiliumEndpoint{
					Name: "cep",
					Networking: &v2.EndpointNetworking{
						Addressing: v2.AddressPairList{
							{IPV6: ipv6Addr1_1.String()},
						},
					},
				},
			),
			newCES: newCES("ces", testNamespace,
				v2alpha1.CoreCiliumEndpoint{
					Name:       "cep",
					IdentityID: 1,
					Networking: &v2.EndpointNetworking{
						Addressing: v2.AddressPairList{
							{IPV4: ipv4Addr.String()},
						},
					},
				},
				v2alpha1.CoreCiliumEndpoint{
					Name: "cep",
					Networking: &v2.EndpointNetworking{
						Addressing: v2.AddressPairList{
							{IPV6: ipv6Addr1_1.String()},
						},
					},
				},
			),
			expectUpdates: []endpointUpdate{
				{
					OldEP: newCiliumEndpoint("cep", testNamespace, WithMultiNetworking(ipv4Addr)),
					NewEP: newCiliumEndpoint("cep", testNamespace, WithID(1), WithMultiNetworking(ipv4Addr)),
				},
			},
			expectedCurrentCES: map[string]string{
				"default/cep1-1-1-1": "ces",
				"default/cep1--1":    "ces",
			},
		},
		{
			name: "no_changes",
			oldCES: newCES("ces", testNamespace,
				v2alpha1.CoreCiliumEndpoint{
					Name: "cep",
					Networking: &v2.EndpointNetworking{
						Addressing: v2.AddressPairList{
							{IPV4: ipv4Addr.String()},
						},
					},
				},
				v2alpha1.CoreCiliumEndpoint{
					Name: "cep",
					Networking: &v2.EndpointNetworking{
						Addressing: v2.AddressPairList{
							{IPV6: ipv6Addr1_1.String()},
						},
					},
				},
			),
			newCES: newCES("ces", testNamespace,
				v2alpha1.CoreCiliumEndpoint{
					Name: "cep",
					Networking: &v2.EndpointNetworking{
						Addressing: v2.AddressPairList{
							{IPV4: ipv4Addr.String()},
						},
					},
				},
				v2alpha1.CoreCiliumEndpoint{
					Name: "cep",
					Networking: &v2.EndpointNetworking{
						Addressing: v2.AddressPairList{
							{IPV6: ipv6Addr1_1.String()},
						},
					},
				},
			),
			expectedCurrentCES: map[string]string{
				"default/cep1-1-1-1": "ces",
				"default/cep1--1":    "ces",
			},
		},
		{
			name: "add_cep2",
			oldCES: newCES("ces", testNamespace,
				v2alpha1.CoreCiliumEndpoint{
					Name: "cep",
					Networking: &v2.EndpointNetworking{
						Addressing: v2.AddressPairList{
							{IPV4: ipv4Addr.String()},
						},
					},
				},
			),
			newCES: newCES("ces", testNamespace,
				v2alpha1.CoreCiliumEndpoint{
					Name: "cep",
					Networking: &v2.EndpointNetworking{
						Addressing: v2.AddressPairList{
							{IPV4: ipv4Addr.String()},
						},
					},
				},
				v2alpha1.CoreCiliumEndpoint{
					Name: "cep",
					Networking: &v2.EndpointNetworking{
						Addressing: v2.AddressPairList{
							{IPV6: ipv6Addr1_1.String()},
						},
					},
				},
			),
			expectUpdates: []endpointUpdate{
				{NewEP: newCiliumEndpoint("cep", testNamespace, WithMultiNetworking(ipv6Addr1_1))},
			},
			expectedCurrentCES: map[string]string{
				"default/cep1-1-1-1": "ces",
				"default/cep1--1":    "ces",
			},
		},
		{
			name: "delete_cep2",
			oldCES: newCES("ces", testNamespace,
				v2alpha1.CoreCiliumEndpoint{
					Name: "cep",
					Networking: &v2.EndpointNetworking{
						Addressing: v2.AddressPairList{
							{IPV4: ipv4Addr.String()},
						},
					},
				},
				v2alpha1.CoreCiliumEndpoint{
					Name: "cep",
					Networking: &v2.EndpointNetworking{
						Addressing: v2.AddressPairList{
							{IPV6: ipv6Addr1_1.String()},
						},
					},
				},
			),
			newCES: newCES("ces", testNamespace,
				v2alpha1.CoreCiliumEndpoint{
					Name: "cep",
					Networking: &v2.EndpointNetworking{
						Addressing: v2.AddressPairList{
							{IPV4: ipv4Addr.String()},
						},
					},
				},
			),
			expectDeleted: []*types.CiliumEndpoint{
				newCiliumEndpoint("cep", testNamespace, WithMultiNetworking(ipv6Addr1_1)),
			},
			expectedCurrentCES: map[string]string{
				"default/cep1-1-1-1": "ces",
			},
		},
		{
			name: "add_update_delete",
			oldCES: newCES("ces", testNamespace,
				v2alpha1.CoreCiliumEndpoint{
					Name: "cep",
					Networking: &v2.EndpointNetworking{
						Addressing: v2.AddressPairList{
							{IPV4: ipv4Addr.String()},
						},
					},
				},
				v2alpha1.CoreCiliumEndpoint{
					Name: "cep",
					Networking: &v2.EndpointNetworking{
						Addressing: v2.AddressPairList{
							{IPV6: ipv6Addr1_1.String()},
						},
					},
				},
			),
			newCES: newCES("ces", testNamespace,
				v2alpha1.CoreCiliumEndpoint{
					Name:       "cep",
					IdentityID: 1,
					Networking: &v2.EndpointNetworking{
						Addressing: v2.AddressPairList{
							{IPV4: ipv4Addr.String()},
						},
					},
				},
				v2alpha1.CoreCiliumEndpoint{
					Name: "cep",
					Networking: &v2.EndpointNetworking{
						Addressing: v2.AddressPairList{
							{IPV6: ipv6Addr2_2.String()},
						},
					},
				},
			),
			expectUpdates: []endpointUpdate{
				{
					NewEP: newCiliumEndpoint("cep", testNamespace, WithMultiNetworking(ipv6Addr2_2)),
				},
				{
					OldEP: newCiliumEndpoint("cep", testNamespace, WithMultiNetworking(ipv4Addr)),
					NewEP: newCiliumEndpoint("cep", testNamespace, WithID(1), WithMultiNetworking(ipv4Addr)),
				},
			},
			expectDeleted: []*types.CiliumEndpoint{
				newCiliumEndpoint("cep", testNamespace, WithMultiNetworking(ipv6Addr1_1)),
			},
			expectedCurrentCES: map[string]string{
				"default/cep1-1-1-1": "ces",
				"default/cep2--2":    "ces",
			},
		},
		{
			name: "keep_local_cep2",
			local: []cacheEntry{
				{Key: "default/cep1--1"},
			},
			oldCES: newCES("ces", testNamespace,
				v2alpha1.CoreCiliumEndpoint{
					Name: "cep",
					Networking: &v2.EndpointNetworking{
						Addressing: v2.AddressPairList{
							{IPV4: ipv4Addr.String()},
						},
					},
				},
				v2alpha1.CoreCiliumEndpoint{
					Name: "cep",
					Networking: &v2.EndpointNetworking{
						Addressing: v2.AddressPairList{
							{IPV6: ipv6Addr1_1.String()},
						},
					},
				},
			),
			newCES: newCES("ces", testNamespace,
				v2alpha1.CoreCiliumEndpoint{
					Name: "cep",
					Networking: &v2.EndpointNetworking{
						Addressing: v2.AddressPairList{
							{IPV4: ipv4Addr.String()},
						},
					},
				},
			),
			expectedCurrentCES: map[string]string{
				"default/cep1-1-1-1": "ces",
				"default/cep1--1":    "ces",
			},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			watcher := newFakeEPWatcher()
			m := &cepToCESmap{
				cepMap:     make(map[string]cesToCEPRef),
				currentCES: make(map[string]string),
			}
			subscriber := &cesSubscriber{
				epWatcher: watcher,
				epCache:   newFakeEndpointCache(tc.local...),
				cepMap:    m,
			}
			// Initialize state, but do not record the events.
			subscriber.OnAdd(tc.oldCES)
			watcher.reset()

			subscriber.OnUpdate(tc.oldCES, tc.newCES)

			if diff := cmp.Diff(tc.expectUpdates, watcher.updates, cmpopts.SortSlices(updateLess)); diff != "" {
				t.Errorf("Unexpected CEP updates(s) (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(tc.expectDeleted, watcher.deleted); diff != "" {
				t.Errorf("Unexpected CEP deletion(s) (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(tc.expectedCurrentCES, m.currentCES); diff != "" {
				t.Fatalf("Unexpected CEP to CES mapping (-want +got):\n%s", diff)
			}
		})
	}
}

func TestCESSubscriber_MultiNetwork_OnDelete(t *testing.T) {
	testCases := []struct {
		name          string
		local         []cacheEntry
		ces           *v2alpha1.CiliumEndpointSlice
		expectDeleted []*types.CiliumEndpoint
		// Expected cepToCESmap.expectedCurrentCES
		expectedCurrentCES map[string]string
	}{
		{
			name: "one_cep",
			ces: newCES("ces", testNamespace, v2alpha1.CoreCiliumEndpoint{
				Name: "cep",
				Networking: &v2.EndpointNetworking{
					Addressing: v2.AddressPairList{
						{IPV4: ipv4Addr.String()},
					},
				},
			}),
			expectDeleted: []*types.CiliumEndpoint{
				newCiliumEndpoint("cep", testNamespace, WithMultiNetworking(ipv4Addr)),
			},
			expectedCurrentCES: map[string]string{},
		},
		{
			name: "two_ceps",
			ces: newCES("ces", testNamespace,
				v2alpha1.CoreCiliumEndpoint{
					Name: "cep",
					Networking: &v2.EndpointNetworking{
						Addressing: v2.AddressPairList{
							{IPV4: ipv4Addr.String()},
						},
					},
				},
				v2alpha1.CoreCiliumEndpoint{
					Name: "cep",
					Networking: &v2.EndpointNetworking{
						Addressing: v2.AddressPairList{
							{IPV6: ipv6Addr1_1.String()},
						},
					},
				},
			),
			expectDeleted: []*types.CiliumEndpoint{
				newCiliumEndpoint("cep", testNamespace, WithMultiNetworking(ipv4Addr)),
				newCiliumEndpoint("cep", testNamespace, WithMultiNetworking(ipv6Addr1_1)),
			},
			expectedCurrentCES: map[string]string{},
		},
		{
			name: "keep_cep1",
			local: []cacheEntry{
				{Key: "default/cep1-1-1-1"},
			},
			ces: newCES("ces", testNamespace,
				v2alpha1.CoreCiliumEndpoint{
					Name: "cep",
					Networking: &v2.EndpointNetworking{
						Addressing: v2.AddressPairList{
							{IPV4: ipv4Addr.String()},
						},
					},
				},
				v2alpha1.CoreCiliumEndpoint{
					Name: "cep",
					Networking: &v2.EndpointNetworking{
						Addressing: v2.AddressPairList{
							{IPV6: ipv6Addr1_1.String()},
						},
					},
				},
			),
			expectDeleted: []*types.CiliumEndpoint{
				newCiliumEndpoint("cep", testNamespace, WithMultiNetworking(ipv6Addr1_1)),
			},
			expectedCurrentCES: map[string]string{
				"default/cep1-1-1-1": "ces",
			},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			watcher := newFakeEPWatcher()
			m := &cepToCESmap{
				cepMap:     make(map[string]cesToCEPRef),
				currentCES: make(map[string]string),
			}
			subscriber := &cesSubscriber{
				epWatcher: watcher,
				epCache:   newFakeEndpointCache(tc.local...),
				cepMap:    m,
			}
			// Initialize state, but do not record the events.
			subscriber.OnAdd(tc.ces)
			watcher.reset()

			subscriber.OnDelete(tc.ces)

			if diff := cmp.Diff(tc.expectDeleted, watcher.deleted); diff != "" {
				t.Errorf("Unexpected CEP deletion(s) (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(tc.expectedCurrentCES, m.currentCES); diff != "" {
				t.Fatalf("Unexpected CEP to CES mapping (-want +got):\n%s", diff)
			}
		})
	}
}
