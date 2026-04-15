package clustermesh

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	cmconfig "github.com/cilium/cilium/pkg/clustermesh/config"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/k8s/types"
	"github.com/cilium/cilium/pkg/kvstore/store"
)

type mockSyncStore struct {
	deletedKeys  []string
	upsertedKeys []string
}

func (m *mockSyncStore) Run(ctx context.Context) {}
func (m *mockSyncStore) UpsertKey(ctx context.Context, key store.Key) error {
	m.upsertedKeys = append(m.upsertedKeys, key.GetKeyName())
	return nil
}
func (m *mockSyncStore) DeleteKey(ctx context.Context, key store.NamedKey) error {
	m.deletedKeys = append(m.deletedKeys, key.GetKeyName())
	return nil
}
func (m *mockSyncStore) Synced(ctx context.Context, callbacks ...func(ctx context.Context)) error {
	return nil
}

func TestIdentitySynchronizer_Upsert(t *testing.T) {
	tests := []struct {
		name                 string
		identity             *ciliumv2.CiliumIdentity
		expectedUpsertedKeys []string
		expectedDeletedKeys  []string
	}{
		{
			name: "Normal Upsert (Matches)",
			identity: &ciliumv2.CiliumIdentity{
				ObjectMeta: metav1.ObjectMeta{Name: "test-identity"},
				SecurityLabels: map[string]string{
					"k8s:networking.gke.io/network": "secondary",
				},
			},
			expectedUpsertedKeys: []string{"test-identity"},
		},
		{
			name: "Delete Stale (Does Not Match)",
			identity: &ciliumv2.CiliumIdentity{
				ObjectMeta: metav1.ObjectMeta{Name: "test-identity"},
				SecurityLabels: map[string]string{
					"k8s:networking.gke.io/network": "default",
				},
			},
			expectedDeletedKeys: []string{"test-identity"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockStore := &mockSyncStore{}
			gconf := cmconfig.GoogleConfig{
				EndpointLabelSelectors: []string{"networking.gke.io/network=secondary"},
			}
			syncer, err := newGoogleSyncer(context.Background(), gconf, nil, nil)
			require.NoError(t, err)

			is := &identitySynchronizer{
				store:        mockStore,
				encoder:      func(b []byte) string { return string(b) },
				googleSyncer: syncer,
			}

			err = is.upsert(context.Background(), resource.Key{Name: tt.identity.Name}, tt.identity)
			require.NoError(t, err)

			if len(tt.expectedUpsertedKeys) == 0 {
				require.Empty(t, mockStore.upsertedKeys)
			} else {
				require.Equal(t, tt.expectedUpsertedKeys, mockStore.upsertedKeys)
			}

			if len(tt.expectedDeletedKeys) == 0 {
				require.Empty(t, mockStore.deletedKeys)
			} else {
				require.Equal(t, tt.expectedDeletedKeys, mockStore.deletedKeys)
			}
		})
	}
}

func TestEndpointSynchronizer_Upsert(t *testing.T) {
	tests := []struct {
		name                 string
		endpoint             *types.CiliumEndpoint
		initialCache         map[string]ipmap
		expectedUpsertedKeys []string
		expectedDeletedKeys  []string
		expectedCache        map[string]ipmap
	}{
		{
			name: "Normal Upsert (Matches)",
			endpoint: &types.CiliumEndpoint{
				ObjectMeta: slim_metav1.ObjectMeta{
					Name:      "test-cep",
					Namespace: "default",
				},
				Identity: &ciliumv2.EndpointIdentity{
					Labels: []string{"k8s:networking.gke.io/network=secondary"},
				},
				Networking: &ciliumv2.EndpointNetworking{
					Addressing: ciliumv2.AddressPairList{{IPV4: "10.0.0.1"}},
					NodeIP:     "192.168.1.1",
				},
			},
			expectedUpsertedKeys: []string{"10.0.0.1"},
			expectedCache: map[string]ipmap{
				"default/test-cep": {"10.0.0.1": {}},
			},
		},
		{
			name: "Delete Stale (Does Not Match)",
			endpoint: &types.CiliumEndpoint{
				ObjectMeta: slim_metav1.ObjectMeta{
					Name:      "test-cep",
					Namespace: "default",
				},
				Identity: &ciliumv2.EndpointIdentity{
					Labels: []string{"k8s:networking.gke.io/network=default"},
				},
			},
			initialCache: map[string]ipmap{
				"default/test-cep": {"10.0.0.1": {}},
			},
			expectedDeletedKeys: []string{"10.0.0.1"},
			expectedCache:       map[string]ipmap{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockStore := &mockSyncStore{}
			gconf := cmconfig.GoogleConfig{
				EndpointLabelSelectors: []string{"networking.gke.io/network=secondary"},
			}
			syncer, err := newGoogleSyncer(context.Background(), gconf, nil, nil)
			require.NoError(t, err)

			es := &endpointSynchronizer{
				store:        mockStore,
				cache:        make(map[string]ipmap),
				googleSyncer: syncer,
			}

			if tt.initialCache != nil {
				es.cache = tt.initialCache
			}

			err = es.upsert(context.Background(), resource.Key{Name: tt.endpoint.Name, Namespace: tt.endpoint.Namespace}, tt.endpoint)
			require.NoError(t, err)

			if len(tt.expectedUpsertedKeys) == 0 {
				require.Empty(t, mockStore.upsertedKeys)
			} else {
				require.Equal(t, tt.expectedUpsertedKeys, mockStore.upsertedKeys)
			}

			if len(tt.expectedDeletedKeys) == 0 {
				require.Empty(t, mockStore.deletedKeys)
			} else {
				require.Equal(t, tt.expectedDeletedKeys, mockStore.deletedKeys)
			}

			if len(tt.expectedCache) == 0 {
				require.Empty(t, es.cache)
			} else {
				require.Equal(t, tt.expectedCache, es.cache)
			}
		})
	}
}
