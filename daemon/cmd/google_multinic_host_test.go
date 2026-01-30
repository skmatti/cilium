package cmd

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/testutils"
	"github.com/stretchr/testify/require"
)

func (ds *DaemonSuite) TestEnsureMultiNICHostEndpoint(t *testing.T) {
	testutils.PrivilegedTest(t)

	option.Config.EnableGoogleMultiNICHostFirewall = true
	defer func() {
		option.Config.EnableGoogleMultiNICHostFirewall = false
	}()
	identity.InitDefaultHostIdentity()

	testID := identity.NumericIdentity(140)
	testNodeNetwork := "test-node-network1"
	idSet := map[string]string{
		testID.String(): testNodeNetwork,
	}
	require.NoError(t, identity.InitMultiNICHostNumericIdentitySet(idSet))
	defer identity.DeleteReservedIdentity(testID)

	// Test multi nic host endpoint for the default node network.
	networkName := identity.DefaultMultiNICNodeNetwork
	dev := "dev1"
	ep, err := ds.d.EnsureMultiNICHostEndpoint(nil, networkName, dev)
	require.NoError(t, err)
	// New endpoint should not be created.
	require.Equal(t, ep, nil)

	// Test multi nic host endpoint for a network without a reserved identity.
	// In this case, the endpoint continues to use the default host identity and
	// no new host endpoint is created.
	networkName = "other-network"
	dev = "dev1"
	ep, err = ds.d.EnsureMultiNICHostEndpoint(nil, networkName, dev)
	require.NoError(t, err)
	// New endpoint should not be created.
	require.Equal(t, ep, nil)

	// Test multi nic host endpoint being created.
	networkName = testNodeNetwork
	dev = "dev2"
	ep, err = ds.d.EnsureMultiNICHostEndpoint(nil, networkName, dev)
	require.NoError(t, err)
	require.NoError(t, verifyMultiNICHostEP(ep, networkName, dev))
}

func (ds *DaemonSuite) TestEnsureMultiNICHostEndpoint_Errors(t *testing.T) {
	option.Config.EnableGoogleMultiNICHostFirewall = true
	defer func() {
		option.Config.EnableGoogleMultiNICHostFirewall = false
	}()
	identity.InitDefaultHostIdentity()

	testID := identity.NumericIdentity(140)
	testNodeNetwork := "test-node-network1"
	testParentDevice := "device-" + testNodeNetwork

	idSet := map[string]string{
		testID.String(): testNodeNetwork,
	}
	require.NoError(t, identity.InitMultiNICHostNumericIdentitySet(idSet))
	defer identity.DeleteReservedIdentity(testID)

	// Test multi nic host endpoint when it is still being regenerated on agent
	// start up. We should wait for regenation to complete before attempting to
	// create a new host endpoint
	restoredEPs := []*endpoint.Endpoint{
		func() *endpoint.Endpoint {
			ep := &endpoint.Endpoint{}
			ep.SetNodeNetworkName(testNodeNetwork)
			ep.SetIsHost(true)
			return ep
		}(),
	}
	_, err := ds.d.EnsureMultiNICHostEndpoint(restoredEPs, testNodeNetwork, testParentDevice)
	require.ErrorContains(t, err, "wait for multi nic host endpoint for node network test-node-network1 to be restored, will retry")
}

func (ds *DaemonSuite) TestDeleteMultiNICHostEndpoint(t *testing.T) {
	testutils.PrivilegedTest(t)
	option.Config.EnableGoogleMultiNICHostFirewall = true
	defer func() {
		option.Config.EnableGoogleMultiNICHostFirewall = false
	}()
	identity.InitDefaultHostIdentity()
	testNodeNetwork := "test-node-network1"
	testParentDevice := "dev-" + testNodeNetwork
	testID := identity.NumericIdentity(140)

	idSet := map[string]string{
		testID.String(): testNodeNetwork,
	}
	require.NoError(t, identity.InitMultiNICHostNumericIdentitySet(idSet))
	defer identity.DeleteReservedIdentity(testID)

	// Deleting default node network should not delete default host endpoint.
	networkName := identity.DefaultMultiNICNodeNetwork
	device := "dev-" + networkName
	// Precreated default host endpoint.
	createdEP, err := ds.createMultiNICHostEP(t, networkName, device)
	require.NoError(t, err)
	require.NotNil(t, createdEP)
	require.NoError(t, ds.d.DeleteMultiNICHostEndpoint(networkName, device))
	currEP := ds.d.endpointManager.GetHostEndpoint()
	require.NoError(t, verifyMultiNICHostEP(currEP, networkName, device))

	// Delete network not associated with any multi nic host endpoint and verify
	// that no host endpoints are not deleted.
	networkName = "other-network"
	device = "dev-" + networkName
	// Precreate a multi nic host endpoint and verify that it is not deleted.
	createdEP, err = ds.createMultiNICHostEP(t, testNodeNetwork, testParentDevice)
	require.NoError(t, err)
	require.NotNil(t, createdEP)
	require.NoError(t, ds.d.DeleteMultiNICHostEndpoint(networkName, device))
	// Verify that default host endpoint is not deleted.
	hostEP := ds.d.endpointManager.GetHostEndpoint()
	require.NoError(t, verifyMultiNICHostEP(hostEP, "node-network", "dev-node-network"))
	currEP = ds.d.endpointManager.GetMultiNICHostEndpoint(testNodeNetwork)
	require.NoError(t, verifyMultiNICHostEP(currEP, testNodeNetwork, testParentDevice))

	// Delete network associated with multi nic host endpoint and verify that
	// the host endpoint is deleted.
	networkName = testNodeNetwork
	device = "dev-" + networkName
	require.NoError(t, ds.d.DeleteMultiNICHostEndpoint(networkName, device))
	// Verify that default host endpoint is not deleted.
	hostEP = ds.d.endpointManager.GetHostEndpoint()
	require.NoError(t, verifyMultiNICHostEP(hostEP, "node-network", "dev-node-network"))
	// Verify that mutli nic host endpoint is deleted.
	require.Nil(t, ds.d.endpointManager.GetMultiNICHostEndpoint(networkName))
}

func (ds *DaemonSuite) createMultiNICHostEP(t *testing.T, network, device string) (*endpoint.Endpoint, error) {
	epTemplate := getEPTemplate(t, ds.d)
	epTemplate.ContainerID = fmt.Sprintf("container-id-%s", network)
	ep, _, err := ds.d.createEndpoint(context.TODO(), ds, epTemplate)
	if err != nil {
		return nil, err
	}
	ep.SetIsHost(true)
	ep.SetParentDevName(device)
	ep.SetNodeNetworkName(network)
	if ep.IsMultiNICHost() {
		node.AddMultiNICHostDevice(device)
	}
	if err = ds.d.endpointManager.UpdateReferences(ep); err != nil {
		return nil, err
	}
	ep.WaitForIdentity(3 * time.Second)
	if network == identity.DefaultMultiNICNodeNetwork {
		return ds.d.endpointManager.GetHostEndpoint(), nil
	}
	return ds.d.endpointManager.GetMultiNICHostEndpoint(network), nil
}

func verifyMultiNICHostEP(ep *endpoint.Endpoint, network, device string) error {
	if !ep.IsHost() {
		return fmt.Errorf("not a host endpoint")
	}
	if ep.GetNodeNetworkName() != network {
		return fmt.Errorf("unexpected node network %q, want %q", ep.GetNodeNetworkName(), network)
	}
	if ep.GetParentDevName() != device {
		return fmt.Errorf("unexpected parent device %q, want %q", ep.GetParentDevName(), device)
	}
	return nil
}
