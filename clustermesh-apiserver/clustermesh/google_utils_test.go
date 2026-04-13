package clustermesh

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"

	cmconfig "github.com/cilium/cilium/pkg/clustermesh/config"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_labels "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/labels"
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
				"k8s:networking.gke.io/network=default",
			},
		},
	}
	k8sNodeVMEP := &types.CiliumEndpoint{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:      "ep-multinic-k8s-node-vm",
			Namespace: "default",
		},
		Identity: &ciliumv2.EndpointIdentity{
			Labels: []string{
				"k8s:networking.gke.io/network=secondary",
				"k8s:node.virtualmachine.private.gdc.goog/node-pool-role=worker",
			},
		},
	}
	multinicEP := &types.CiliumEndpoint{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:      "ep-multinic",
			Namespace: "default",
		},
		Identity: &ciliumv2.EndpointIdentity{
			Labels: []string{
				"k8s:networking.gke.io/network=secondary",
			},
		},
	}
	projectEP := &types.CiliumEndpoint{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:      "ep-project",
			Namespace: "default",
		},
		Identity: &ciliumv2.EndpointIdentity{
			Labels: []string{
				"k8s:io.cilium.k8s.namespace.labels.resourcemanager.gdc.goog/project-namespace=test-namespace",
				"k8s:networking.gke.io/network=default",
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
			name:        "empty selectors syncs everything",
			ep:          regularEP,
			epSelectors: []string{},
			want:        true,
		},
		{
			name:        "nil endpoint",
			ep:          nil,
			epSelectors: []string{"foo"},
			want:        false,
		},
		{
			name:        "sync project - no match",
			ep:          regularEP,
			epSelectors: []string{"io.cilium.k8s.namespace.labels.resourcemanager.gdc.goog/project-namespace"},
			want:        false,
		},
		{
			name:        "sync project - projectEP",
			ep:          projectEP,
			epSelectors: []string{"io.cilium.k8s.namespace.labels.resourcemanager.gdc.goog/project-namespace"},
			want:        true,
		},
		{
			name: "OR selectors - no match",
			ep:   regularEP,
			epSelectors: []string{
				"io.cilium.k8s.namespace.labels.resourcemanager.gdc.goog/project-namespace",
				"node.virtualmachine.private.gdc.goog/node-pool-role,networking.gke.io/network,networking.gke.io/network!=default",
			},
			want: false,
		},
		{
			name: "OR selectors - match first selector",
			ep:   projectEP,
			epSelectors: []string{
				"io.cilium.k8s.namespace.labels.resourcemanager.gdc.goog/project-namespace",
				"node.virtualmachine.private.gdc.goog/node-pool-role,networking.gke.io/network,networking.gke.io/network!=default",
			},
			want: true,
		},
		{
			name: "OR selectors - match second selector",
			ep:   k8sNodeVMEP,
			epSelectors: []string{
				"io.cilium.k8s.namespace.labels.resourcemanager.gdc.goog/project-namespace",
				"node.virtualmachine.private.gdc.goog/node-pool-role,networking.gke.io/network,networking.gke.io/network!=default",
			},
			want: true,
		},
		{
			name: "OR selectors with negation - match second selector",
			ep:   multinicEP,
			epSelectors: []string{
				"io.cilium.k8s.namespace.labels.resourcemanager.gdc.goog/project-namespace",
				"!node.virtualmachine.private.gdc.goog/node-pool-role,networking.gke.io/network,networking.gke.io/network!=default",
			},
			want: true,
		},
		{
			name: "OR selectors with negation - no match",
			ep:   k8sNodeVMEP,
			epSelectors: []string{
				"io.cilium.k8s.namespace.labels.resourcemanager.gdc.goog/project-namespace",
				"!node.virtualmachine.private.gdc.goog/node-pool-role,networking.gke.io/network,networking.gke.io/network!=default",
			},
			want: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			gconf := cmconfig.GoogleConfig{
				EndpointLabelSelectors: tc.epSelectors,
			}
			syncer, err := newGoogleSyncer(context.Background(), gconf, nil, nil)
			require.NoError(t, err)
			got := syncer.ShouldSyncCEP(tc.ep)
			require.Equal(t, tc.want, got)
		})
	}
}

func TestShouldSyncIdentity(t *testing.T) {
	projectIdentity := &ciliumv2.CiliumIdentity{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "ep-project",
			Namespace: "default",
		},
		SecurityLabels: map[string]string{
			"k8s:networking.gke.io/network": "default",
			"k8s:io.cilium.k8s.namespace.labels.resourcemanager.gdc.goog/project-namespace": "test-namespace",
		},
	}
	multinicIdentity := &ciliumv2.CiliumIdentity{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "ep-multinic",
			Namespace: "default",
		},
		SecurityLabels: map[string]string{
			"k8s:networking.gke.io/network": "secondary",
			"k8s:io.cilium.k8s.namespace.labels.resourcemanager.gdc.goog/project-namespace": "test-namespace",
		},
	}
	k8sNodeVMIdentity := &ciliumv2.CiliumIdentity{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "ep-multinic-k8s-node-vm",
			Namespace: "default",
		},
		SecurityLabels: map[string]string{
			"k8s:networking.gke.io/network": "secondary",
			"k8s:io.cilium.k8s.namespace.labels.resourcemanager.gdc.goog/project-namespace": "test-namespace",
			"k8s:node.virtualmachine.private.gdc.goog/node-pool-role":                       "worker",
		},
	}
	testCases := []struct {
		name        string
		identity    *ciliumv2.CiliumIdentity
		epSelectors []string
		want        bool
	}{
		{
			name:        "empty selectors",
			identity:    projectIdentity,
			epSelectors: []string{},
			want:        true,
		},
		{
			name:        "nil identity",
			identity:    nil,
			epSelectors: []string{"foo"},
			want:        false,
		},
		{
			name:     "multiple selectors - no match",
			identity: projectIdentity,
			epSelectors: []string{
				"io.cilium.k8s.namespace.labels.resourcemanager.gdc.goog/project-namespace,!node.virtualmachine.private.gdc.goog/node-pool-role,networking.gke.io/network!=default",
				"io.cilium.k8s.namespace.labels.resourcemanager.gdc.goog/project-namespace,node.virtualmachine.private.gdc.goog/node-pool-role",
			},
			want: false,
		},
		{
			name:     "multiple selectors - match first",
			identity: multinicIdentity,
			epSelectors: []string{
				"io.cilium.k8s.namespace.labels.resourcemanager.gdc.goog/project-namespace,!node.virtualmachine.private.gdc.goog/node-pool-role,networking.gke.io/network!=default",
				"io.cilium.k8s.namespace.labels.resourcemanager.gdc.goog/project-namespace,node.virtualmachine.private.gdc.goog/node-pool-role",
			},
			want: true,
		},
		{
			name:     "multiple selectors - match second",
			identity: k8sNodeVMIdentity,
			epSelectors: []string{
				"io.cilium.k8s.namespace.labels.resourcemanager.gdc.goog/project-namespace,!node.virtualmachine.private.gdc.goog/node-pool-role,networking.gke.io/network!=default",
				"io.cilium.k8s.namespace.labels.resourcemanager.gdc.goog/project-namespace,node.virtualmachine.private.gdc.goog/node-pool-role",
			},
			want: true,
		},
		{
			name:        "single selector - no match",
			identity:    projectIdentity,
			epSelectors: []string{"networking.gke.io/network=secondary"},
			want:        false,
		},
		{
			name:        "single selector - match",
			identity:    k8sNodeVMIdentity,
			epSelectors: []string{"node.virtualmachine.private.gdc.goog/node-pool-role=worker"},
			want:        true,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			gconf := cmconfig.GoogleConfig{
				EndpointLabelSelectors: tc.epSelectors,
			}
			syncer, err := newGoogleSyncer(context.Background(), gconf, nil, nil)
			require.NoError(t, err)
			got := syncer.ShouldSyncIdentity(tc.identity)
			require.Equal(t, tc.want, got)
		})
	}
}

func TestParseLabelSelectors(t *testing.T) {
	testCases := []struct {
		name              string
		labelSelectorStrs []string
		wantSelectors     []slim_labels.Selector
		wantErrMsg        string
	}{
		{
			name:              "empty",
			labelSelectorStrs: []string{},
			wantSelectors:     []slim_labels.Selector{},
		},
		{
			name:              "single selector",
			labelSelectorStrs: []string{"k1=v1"},
			wantSelectors: func() []slim_labels.Selector {
				s, _ := slim_labels.Parse("k1=v1")
				return []slim_labels.Selector{s}
			}(),
		},
		{
			name:              "multiple selectors",
			labelSelectorStrs: []string{"k1=v1", "k2"},
			wantSelectors: func() []slim_labels.Selector {
				s1, _ := slim_labels.Parse("k1=v1")
				s2, _ := slim_labels.Parse("k2")
				return []slim_labels.Selector{s1, s2}
			}(),
		},
		{
			name:              "selector with space and in operator",
			labelSelectorStrs: []string{"k1=v1,k2,!k3", "k4 in (v4-a, v4-b)"},
			wantSelectors: func() []slim_labels.Selector {
				s1, _ := slim_labels.Parse("k1=v1,k2,!k3")
				s2, _ := slim_labels.Parse("k4 in (v4-a,v4-b)")
				return []slim_labels.Selector{s1, s2}
			}(),
		},
		{
			name:              "selector with notin",
			labelSelectorStrs: []string{"!k2,k3 notin (v3-a,v3-b)"},
			wantSelectors: func() []slim_labels.Selector {
				s, _ := slim_labels.Parse("!k2,k3 notin (v3-a,v3-b)")
				return []slim_labels.Selector{s}
			}(),
		},
		{
			name:              "invalid selector with colon",
			labelSelectorStrs: []string{"k1=v1,"},
			wantErrMsg:        `parse "k1=v1," as label selector`,
		},
		{
			name:              "invalid selector with space",
			labelSelectorStrs: []string{"k1=v1 !k2"},
			wantErrMsg:        `parse "k1=v1 !k2" as label selector`,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			selectors, err := parseLabelSelectors(tc.labelSelectorStrs)
			if tc.wantErrMsg != "" {
				require.Error(t, err)
				require.Contains(t, err.Error(), tc.wantErrMsg)
				return
			}
			require.NoError(t, err)
			for i := range selectors {
				require.Equal(t, tc.wantSelectors[i].String(), selectors[i].String())
			}
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

func TestNewNamespaceCache(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	fakeClientset, _ := k8sClient.NewFakeClientset()
	labels := []string{"resourcemanager.gdc.goog/project-namespace=test-namespace"}

	updateChan := make(chan string, 1)
	onUpdate := func(ns string) {
		updateChan <- ns
	}

	nsCache, err := newNamespaceCache(ctx, fakeClientset, labels, onUpdate)
	require.NoError(t, err)
	require.NotNil(t, nsCache)

	ns := &slim_corev1.Namespace{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name: "test-ns",
			Labels: map[string]string{
				"resourcemanager.gdc.goog/project-namespace": "test-namespace",
			},
		},
	}

	_, err = fakeClientset.Slim().CoreV1().Namespaces().Create(context.Background(), ns, metav1.CreateOptions{})
	require.NoError(t, err)

	select {
	case name := <-updateChan:
		require.Equal(t, "test-ns", name)
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for namespace update")
	}

	// Update namespace labels to no longer match
	ns.Labels = map[string]string{}
	_, err = fakeClientset.Slim().CoreV1().Namespaces().Update(context.Background(), ns, metav1.UpdateOptions{})
	require.NoError(t, err)

	select {
	case name := <-updateChan:
		require.Equal(t, "test-ns", name)
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for namespace update")
	}
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
			syncer, err := newGoogleSyncer(context.Background(), gconf, nil, nil)
			require.NoError(t, err)

			got := syncer.OverrideIdentityLabels(tc.securityLabels)
			require.Equal(t, tc.want, got)
		})
	}
}
