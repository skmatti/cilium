package clustermesh

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	ciliumio "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/k8s/types"
	"github.com/cilium/cilium/pkg/labels"
)

func TestShouldSyncIdentity(t *testing.T) {
	regularIdentity := &ciliumv2.CiliumIdentity{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "ep",
			Namespace: "default",
		},
		SecurityLabels: map[string]string{
			"k8s:networking.gke.io/network": "default",
		},
	}
	multinicIdentity := &ciliumv2.CiliumIdentity{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "ep",
			Namespace: "default",
		},
		SecurityLabels: map[string]string{
			"k8s:networking.gke.io/network": "secondary",
		},
	}
	testCases := []struct {
		name               string
		identity           *ciliumv2.CiliumIdentity
		enableMultiNicSync bool
		want               bool
	}{
		{
			name:               "regular identity with sync disabled",
			identity:           regularIdentity,
			enableMultiNicSync: false,
		},
		{
			name:               "regular identity with sync enabled",
			identity:           regularIdentity,
			enableMultiNicSync: true,
		},
		{
			name:               "multinic identity with sync disabled",
			identity:           multinicIdentity,
			enableMultiNicSync: false,
		},
		{
			name:               "multinic identity with sync enabled",
			identity:           multinicIdentity,
			enableMultiNicSync: true,
			want:               true,
		},
		{
			name:               "nil identity with sync enabled",
			identity:           nil,
			enableMultiNicSync: true,
			want:               false,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ginfo := cmtypes.GoogleConfig{SyncMultiNicEPs: tc.enableMultiNicSync}
			gs, err := newGoogleSyncer(ginfo, nil)
			require.NoError(t, err)
			res := gs.ShouldSyncIdentity(tc.identity)
			require.Equal(t, tc.want, res)
		})
	}
}

func TestShouldSyncCEP(t *testing.T) {
	regularCEP := &types.CiliumEndpoint{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:      "ep",
			Namespace: "default",
		},
	}
	multinicCEP := &types.CiliumEndpoint{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:      "ep",
			Namespace: "default",
			Annotations: map[string]string{
				multinicAnnotation: "true",
			},
		},
	}
	testCases := []struct {
		name               string
		cep                *types.CiliumEndpoint
		enableMultiNicSync bool
		want               bool
	}{
		{
			name:               "regular cep with sync disabled",
			cep:                regularCEP,
			enableMultiNicSync: false,
			want:               false,
		},
		{
			name:               "regular cep with sync enabled",
			cep:                regularCEP,
			enableMultiNicSync: true,
			want:               false,
		},
		{
			name:               "multinic cep with sync disabled",
			cep:                multinicCEP,
			enableMultiNicSync: false,
			want:               false,
		},
		{
			name:               "multinic cep with sync enabled",
			cep:                multinicCEP,
			enableMultiNicSync: true,
			want:               true,
		},
		{
			name:               "nil cep with sync enabled",
			cep:                nil,
			enableMultiNicSync: true,
			want:               false,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ginfo := cmtypes.GoogleConfig{SyncMultiNicEPs: tc.enableMultiNicSync}
			gs, err := newGoogleSyncer(ginfo, nil)
			require.NoError(t, err)
			res := gs.ShouldSyncCEP(tc.cep)
			require.Equal(t, tc.want, res)
		})
	}
}

func TestBuildLabelSelector(t *testing.T) {
	tests := []struct {
		name    string
		labels  []string
		want    string
		wantErr bool
	}{
		{
			name:   "single label",
			labels: []string{"foo"},
			want:   "foo",
		},
		{
			name:   "multiple labels",
			labels: []string{"foo", "bar"},
			want:   "bar,foo",
		},
		{
			name:   "empty labels",
			labels: []string{},
			want:   "",
		},
		{
			name:    "invalid label",
			labels:  []string{"invalid label"},
			wantErr: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := buildLabelSelector(tc.labels)
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.want, got.String())
		})
	}
}

func TestGetIdentityNamespace(t *testing.T) {
	nsLabelKey := strings.TrimSuffix(labels.GenerateK8sLabelString(ciliumio.PodNamespaceLabel, ""), "=")
	tests := []struct {
		name     string
		identity *ciliumv2.CiliumIdentity
		want     string
		wantErr  bool
	}{
		{
			name: "namespace label exists",
			identity: &ciliumv2.CiliumIdentity{
				ObjectMeta: metav1.ObjectMeta{Name: "test-id"},
				SecurityLabels: map[string]string{
					nsLabelKey: "test-ns",
				},
			},
			want: "test-ns",
		},
		{
			name: "namespace label does not exist",
			identity: &ciliumv2.CiliumIdentity{
				ObjectMeta: metav1.ObjectMeta{Name: "test-id"},
				SecurityLabels: map[string]string{
					"some-other-label": "value",
				},
			},
			wantErr: true,
		},
		{
			name: "no security labels",
			identity: &ciliumv2.CiliumIdentity{
				ObjectMeta: metav1.ObjectMeta{Name: "test-id"},
			},
			wantErr: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := getIdentityNamespace(tc.identity)
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.want, got)
		})
	}
}

func TestShouldSyncNamespace(t *testing.T) {
	gs := &googleSyncer{}

	gs.namespaceCache = cache.NewStore(cache.MetaNamespaceKeyFunc)
	ns := &slim_corev1.Namespace{ObjectMeta: slim_metav1.ObjectMeta{Name: "existing-ns"}}
	gs.namespaceCache.Add(ns)

	require.True(t, gs.ShouldSyncNamespace("existing-ns"))
	require.False(t, gs.ShouldSyncNamespace("non-existing-ns"))

	gs.namespaceCache = nil
	require.True(t, gs.ShouldSyncNamespace("any-ns"))
}
