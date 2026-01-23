package endpoint

import (
	"encoding/json"
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

func (s *EndpointSuite) testToSerializedEndpointIfNameInPodPersistence(t *testing.T) {
	ep := NewTestEndpointWithState(t, s, s, testipcache.NewMockIPCache(), &FakeEndpointProxy{}, testidentity.NewMockIdentityAllocator(nil), 123, StateReady)
	ep.containerIfName = "eth0"

	serialized := ep.toSerializedEndpoint()

	// Verify that both new and old fields are populated
	require.Equal(t, "eth0", serialized.ContainerIfName, "ContainerIfName should be populated")
	require.Equal(t, "eth0", serialized.IfNameInPod, "IfNameInPod should be populated for backward compatibility")
}

func (s *EndpointSuite) testDowngradeUpgradeSimulation(t *testing.T) {
	// 1. Start with 1.16 Endpoint
	ep := NewTestEndpointWithState(t, s, s, testipcache.NewMockIPCache(), &FakeEndpointProxy{}, testidentity.NewMockIdentityAllocator(nil), 123, StateReady)
	ep.containerIfName = "eth0"

	// 2. Serialize (1.16 Saving)
	serialized116 := ep.toSerializedEndpoint()
	json116, err := json.Marshal(serialized116)
	require.NoError(t, err)

	// 3. Simulate 1.13 Reading (Downgrade)
	// 1.13 struct didn't have ContainerIfName
	type legacySerializableEndpoint struct {
		ID          uint16
		IfNameInPod string
		// Other fields omitted for brevity, checking partial unmarshal
	}
	var legacyEp legacySerializableEndpoint
	err = json.Unmarshal(json116, &legacyEp)
	require.NoError(t, err)

	// Verify 1.13 sees the data
	require.Equal(t, "eth0", legacyEp.IfNameInPod, "1.13 agent should see the interface name in IfNameInPod")

	// 4. Simulate 1.13 Saving (Restart/Update in 1.13)
	json113, err := json.Marshal(legacyEp)
	require.NoError(t, err)

	// 5. Simulate 1.16 Reading 1.13 State (Upgrade back to 1.16)
	var restoredSerialized116 serializableEndpoint
	err = json.Unmarshal(json113, &restoredSerialized116)
	require.NoError(t, err)

	restoredEp := NewTestEndpointWithState(t, s, s, testipcache.NewMockIPCache(), &FakeEndpointProxy{}, testidentity.NewMockIdentityAllocator(nil), 123, StateReady)
	restoredEp.fromSerializedEndpoint(&restoredSerialized116)

	// Verify data is preserved after round trip
	require.Equal(t, "eth0", restoredEp.containerIfName, "Data should be preserved after 1.16 -> 1.13 -> 1.16 cycle")
}

func TestToSerializedEndpointIfNameInPodPersistence(t *testing.T) {
	s := setupEndpointSuite(t)
	s.testToSerializedEndpointIfNameInPodPersistence(t)
	s.testDowngradeUpgradeSimulation(t)
}
