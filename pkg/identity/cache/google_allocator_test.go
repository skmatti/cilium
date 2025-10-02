package cache

import (
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/allocator"
	"github.com/cilium/cilium/pkg/identity/key"
	"github.com/cilium/cilium/pkg/idpool"
	ciliumio "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	"github.com/cilium/cilium/pkg/labels"
)

type mockCacheMutations struct {
	allocator.CacheMutations
	existing map[idpool.ID]bool
	// ID -> called or not
	onAddCalled    map[int]bool
	onModifyCalled map[int]bool
	onDeleteCalled map[int]bool
}

func newMockCacheMutations() *mockCacheMutations {
	return &mockCacheMutations{
		existing:       make(map[idpool.ID]bool),
		onAddCalled:    make(map[int]bool),
		onModifyCalled: make(map[int]bool),
		onDeleteCalled: make(map[int]bool),
	}
}

func (m *mockCacheMutations) OnUpsert(id idpool.ID, key allocator.AllocatorKey) {
	if _, ok := m.existing[id]; ok {
		m.onModifyCalled[int(id)] = true
	} else {
		m.onAddCalled[int(id)] = true
	}
	m.existing[id] = true
}

func (m *mockCacheMutations) OnDelete(id idpool.ID, key allocator.AllocatorKey) {
	m.onDeleteCalled[int(id)] = true
	delete(m.existing, id)
}

type nonGlobalKey struct{}

func (k *nonGlobalKey) GetKey() string                                           { return "non-global" }
func (k *nonGlobalKey) PutKey(v string) allocator.AllocatorKey                   { return k }
func (k *nonGlobalKey) GetAsMap() map[string]string                              { return nil }
func (k *nonGlobalKey) PutKeyFromMap(v map[string]string) allocator.AllocatorKey { return k }
func (k *nonGlobalKey) PutValue(key, value any) allocator.AllocatorKey           { return k }
func (k *nonGlobalKey) Value(key any) any                                        { return nil }
func (k *nonGlobalKey) String() string                                           { return "non-global" }

func TestCacheMutationsFilter_OnAdd(t *testing.T) {
	namespaceToSkip := "kube-system"
	matchingLabels := labels.ParseLabelArray("k8s:foo=bar", "k8s:"+ciliumio.PodNamespaceMetaNameLabel+"="+namespaceToSkip)
	nonMatchingLabels := labels.ParseLabelArray("k8s:foo=bar", "k8s:"+ciliumio.PodNamespaceMetaNameLabel+"=default")
	noNSLabels := labels.ParseLabelArray("k8s:foo=bar")

	matchingKey := &key.GlobalIdentity{LabelArray: matchingLabels}
	nonMatchingKey := &key.GlobalIdentity{LabelArray: nonMatchingLabels}
	noNSKey := &key.GlobalIdentity{LabelArray: noNSLabels}

	tests := []struct {
		name               string
		key                allocator.AllocatorKey
		shouldCallOnAdd    bool
		shouldCallOnDelete bool
	}{
		{
			name:               "namespace matches skip",
			key:                matchingKey,
			shouldCallOnAdd:    false,
			shouldCallOnDelete: true,
		},
		{
			name:               "namespace does not match skip",
			key:                nonMatchingKey,
			shouldCallOnAdd:    true,
			shouldCallOnDelete: false,
		},
		{
			name:               "no namespace label",
			key:                noNSKey,
			shouldCallOnAdd:    true,
			shouldCallOnDelete: false,
		},
		{
			name:               "non-global key type",
			key:                &nonGlobalKey{},
			shouldCallOnAdd:    true,
			shouldCallOnDelete: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := newMockCacheMutations()
			filter := &cacheMutationsFilter{
				CacheMutations:   mock,
				namespacesToSkip: []string{namespaceToSkip},
				log:              logrus.NewEntry(logrus.New()),
			}

			// Test OnAdd
			id := 1
			filter.OnUpsert(idpool.ID(id), tt.key)
			require.Equal(t, tt.shouldCallOnAdd, mock.onAddCalled[id], "Unexpected OnAdd call")
			require.Equal(t, tt.shouldCallOnDelete, mock.onDeleteCalled[id], "Unexpected OnDelete call")
			require.False(t, mock.onModifyCalled[id], "OnModify should not have been called")
		})
	}
}

func TestCacheMutationsFilter_OnModify(t *testing.T) {
	namespaceToSkip := "kube-system"
	matchingLabels := labels.ParseLabelArray("k8s:foo=bar", "k8s:"+ciliumio.PodNamespaceMetaNameLabel+"="+namespaceToSkip)
	nonMatchingLabels := labels.ParseLabelArray("k8s:foo=bar", "k8s:"+ciliumio.PodNamespaceMetaNameLabel+"=default")
	noNSLabels := labels.ParseLabelArray("k8s:foo=bar")

	matchingKey := &key.GlobalIdentity{LabelArray: matchingLabels}
	nonMatchingKey := &key.GlobalIdentity{LabelArray: nonMatchingLabels}
	noNSKey := &key.GlobalIdentity{LabelArray: noNSLabels}

	tests := []struct {
		name               string
		key                allocator.AllocatorKey
		shouldCallOnModify bool
		shouldCallOnDelete bool
	}{
		{
			name:               "namespace matches skip",
			key:                matchingKey,
			shouldCallOnModify: false,
			shouldCallOnDelete: true,
		},
		{
			name:               "namespace does not match skip",
			key:                nonMatchingKey,
			shouldCallOnModify: true,
			shouldCallOnDelete: false,
		},
		{
			name:               "no namespace label",
			key:                noNSKey,
			shouldCallOnModify: true,
			shouldCallOnDelete: false,
		},
		{
			name:               "non-global key type",
			key:                &nonGlobalKey{},
			shouldCallOnModify: true,
			shouldCallOnDelete: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := newMockCacheMutations()
			filter := &cacheMutationsFilter{
				CacheMutations:   mock,
				namespacesToSkip: []string{namespaceToSkip},
				log:              logrus.NewEntry(logrus.New()),
			}

			// Pre-populate the mock to simulate a modification
			id := 2
			mock.existing[idpool.ID(id)] = true

			filter.OnUpsert(idpool.ID(id), tt.key)
			require.Equal(t, tt.shouldCallOnModify, mock.onModifyCalled[id], "Unexpected OnModify call")
			require.Equal(t, tt.shouldCallOnDelete, mock.onDeleteCalled[id], "Unexpected OnDelete call")
			require.False(t, mock.onAddCalled[id], "OnAdd should not have been called")
		})
	}
}
