package endpoint

import (
	"testing"

	testidentity "github.com/cilium/cilium/pkg/testutils/identity"
	testipcache "github.com/cilium/cilium/pkg/testutils/ipcache"
	"github.com/stretchr/testify/require"
)

func (s *EndpointSuite) testRestoreIfNameInPod(t *testing.T) {
	// This is a serializableEndpoint with only the old field.
	oldEp := &serializableEndpoint{
		ID:          123,
		IfNameInPod: "eth0_old",
	}

	// This is a serializableEndpoint with only the new field.
	newEp := &serializableEndpoint{
		ID:              124,
		ContainerIfName: "eth0_new",
	}

	// This is a serializableEndpoint with both fields.
	bothEp := &serializableEndpoint{
		ID:              125,
		IfNameInPod:     "eth0_old",
		ContainerIfName: "eth0_new",
	}

	testcases := []struct {
		name           string
		serializedEP   *serializableEndpoint
		expectedIfName string
	}{
		{
			name:           "restoring from old endpoint with IfNameInPod",
			serializedEP:   oldEp,
			expectedIfName: "eth0_old",
		},
		{
			name:           "restoring from new endpoint with ContainerIfName",
			serializedEP:   newEp,
			expectedIfName: "eth0_new",
		},
		{
			name:           "restoring from new endpoint with both fields set",
			serializedEP:   bothEp,
			expectedIfName: "eth0_new",
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			ep := NewTestEndpointWithState(t, s, s, testipcache.NewMockIPCache(), &FakeEndpointProxy{}, testidentity.NewMockIdentityAllocator(nil), tc.serializedEP.ID, StateReady)
			ep.fromSerializedEndpoint(tc.serializedEP)
			require.Equal(t, tc.expectedIfName, ep.containerIfName)
		})
	}
}

func TestRestoreIfNameInPod(t *testing.T) {
	s := setupEndpointSuite(t)
	s.testRestoreIfNameInPod(t)
}
