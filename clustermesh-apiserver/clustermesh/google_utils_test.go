package clustermesh

import (
	"testing"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"

	cmconfig "github.com/cilium/cilium/pkg/clustermesh/config"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/k8s/types"
)

func TestShouldSyncCEP(t *testing.T) {
	regularEP := &types.CiliumEndpoint{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:      "ep",
			Namespace: "default",
		},
		Identity: &ciliumv2.EndpointIdentity{
			Labels: []string{
				"k8s:io.cilium.k8s.namespace.labels.resourcemanager.gdc.goog/project-namespace=test-namespace",
				"k8s:networking.gke.io/network=default",
			},
		},
	}
	multinicEP := &types.CiliumEndpoint{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:      "ep",
			Namespace: "default",
		},
		Identity: &ciliumv2.EndpointIdentity{
			Labels: []string{
				"k8s:io.cilium.k8s.namespace.labels.resourcemanager.gdc.goog/project-namespace=test-namespace",
				"k8s:networking.gke.io/network=secondary",
			},
		},
	}
	testCases := []struct {
		name        string
		ep          *types.CiliumEndpoint
		epSelectors []string
		want        bool
	}{
		{
			name:        "empty_selectors",
			ep:          regularEP,
			epSelectors: []string{},
			want:        true,
		},
		{
			name: "dont_sync_defaultnic_endpoint",
			ep:   regularEP,
			epSelectors: []string{
				"k8s:io.cilium.k8s.namespace.labels.resourcemanager.gdc.goog/project-namespace !k8s:node.virtualmachine.private.gdc.goog/node-pool-role k8s:networking.gke.io/network!=default",
			},
			want: false,
		},
		{
			name: "should_sync_multinic_endpoint",
			ep:   multinicEP,
			epSelectors: []string{
				"k8s:io.cilium.k8s.namespace.labels.resourcemanager.gdc.goog/project-namespace !k8s:node.virtualmachine.private.gdc.goog/node-pool-role k8s:networking.gke.io/network!=default",
			},
			want: true,
		},
		{
			name:        "nil_cep",
			ep:          nil,
			epSelectors: []string{},
			want:        false,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			gconf := cmconfig.GoogleConfig{
				EndpointLabelSelectors: tc.epSelectors,
			}
			syncer, err := newGoogleSyncer(gconf, nil)
			require.NoError(t, err)
			res := syncer.ShouldSyncCEP(tc.ep)
			require.Equal(t, tc.want, res)
		})
	}
}

func TestShouldSyncIdentity(t *testing.T) {
	regularIdentity := &ciliumv2.CiliumIdentity{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "ep",
			Namespace: "default",
		},
		SecurityLabels: map[string]string{
			"k8s:networking.gke.io/network": "default",
			"k8s:io.cilium.k8s.namespace.labels.resourcemanager.gdc.goog/project-namespace": "test-namespace",
		},
	}
	multinicIdentity := &ciliumv2.CiliumIdentity{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "ep",
			Namespace: "default",
		},
		SecurityLabels: map[string]string{
			"k8s:networking.gke.io/network": "secondary",
			"k8s:io.cilium.k8s.namespace.labels.resourcemanager.gdc.goog/project-namespace": "test-namespace",
		},
	}
	testCases := []struct {
		name        string
		identity    *ciliumv2.CiliumIdentity
		epSelectors []string
		want        bool
	}{
		{
			name:        "empty_selectors",
			identity:    regularIdentity,
			epSelectors: []string{},
			want:        true,
		},
		{
			name:     "dont_sync_defaultnic_endpoint",
			identity: regularIdentity,
			epSelectors: []string{
				"k8s:io.cilium.k8s.namespace.labels.resourcemanager.gdc.goog/project-namespace !k8s:node.virtualmachine.private.gdc.goog/node-pool-role k8s:networking.gke.io/network!=default",
			},
			want: false,
		},
		{
			name: "should_sync_multinic_identity",
			epSelectors: []string{
				"k8s:io.cilium.k8s.namespace.labels.resourcemanager.gdc.goog/project-namespace !k8s:node.virtualmachine.private.gdc.goog/node-pool-role k8s:networking.gke.io/network!=default",
			},
			identity: multinicIdentity,
			want:     true,
		},
		{
			name:        "nil_identity",
			identity:    nil,
			epSelectors: []string{},
			want:        false,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			gconf := cmconfig.GoogleConfig{
				EndpointLabelSelectors: tc.epSelectors,
			}
			syncer, err := newGoogleSyncer(gconf, nil)
			require.NoError(t, err)
			res := syncer.ShouldSyncIdentity(tc.identity)
			require.Equal(t, tc.want, res)
		})
	}
}
func TestShouldSyncNamespace(t *testing.T) {
	syncer := &googleSyncer{}
	syncer.namespaceCache = cache.NewStore(cache.MetaNamespaceKeyFunc)
	ns := &slim_corev1.Namespace{ObjectMeta: slim_metav1.ObjectMeta{Name: "existing-ns"}}
	syncer.namespaceCache.Add(ns)
	require.True(t, syncer.ShouldSyncNamespace("existing-ns"))
	require.False(t, syncer.ShouldSyncNamespace("non-existing-ns"))
	syncer.namespaceCache = nil
	require.True(t, syncer.ShouldSyncNamespace("any-ns"))
}

func TestOverrideIdentityLabels(t *testing.T) {
	testCases := []struct {
		name                   string
		overrideIdentityLabels map[string]string
		securityLabels         map[string]string
		want                   map[string]string
	}{
		{
			name:                   "no_override",
			overrideIdentityLabels: map[string]string{},
			securityLabels: map[string]string{
				"k8s:foo": "bar",
			},
			want: map[string]string{
				"k8s:foo": "bar",
			},
		},
		{
			name: "add_new_label",
			overrideIdentityLabels: map[string]string{
				"k8s:new": "label",
			},
			securityLabels: map[string]string{
				"k8s:foo": "bar",
			},
			want: map[string]string{
				"k8s:foo": "bar",
				"k8s:new": "label",
			},
		},
		{
			name: "override_existing_label",
			overrideIdentityLabels: map[string]string{
				"k8s:foo": "new-bar",
			},
			securityLabels: map[string]string{
				"k8s:foo": "bar",
			},
			want: map[string]string{
				"k8s:foo": "new-bar",
			},
		},
		{
			name: "nil_security_labels",
			overrideIdentityLabels: map[string]string{
				"k8s:new": "label",
			},
			securityLabels: nil,
			want: map[string]string{
				"k8s:new": "label",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			gconf := cmconfig.GoogleConfig{
				OverrideIdentityLabels: tc.overrideIdentityLabels,
			}
			syncer, err := newGoogleSyncer(gconf, nil)
			require.NoError(t, err)

			got := syncer.OverrideIdentityLabels(tc.securityLabels)
			require.Equal(t, tc.want, got)
		})
	}
}
