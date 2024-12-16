package cmd

import (
	"context"
	"testing"

	apiEndpoint "github.com/cilium/cilium/api/v1/server/restapi/endpoint"
	"github.com/cilium/cilium/pkg/gke/features"
	"github.com/cilium/cilium/pkg/testutils"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/pointer"

	networkv1alpha1 "gke-internal.googlesource.com/anthos-networking/apis/network/v1alpha1"
)

func (ds *DaemonSuite) TestCreateEndpointQueue(t *testing.T) {
	epTemplate := getEPTemplate(t, ds.d)
	epTemplate.K8sPodName = "foo-pod"
	epTemplate.K8sNamespace = "foo-ns"
	// Create the primary endpoint
	err := ds.d.CreateEndpoint(context.TODO(), epTemplate)
	require.Empty(t, err)
}

func (ds *DaemonSuite) TestCreateMultiNICEndpointsNoK8sEnabled(t *testing.T) {
	testutils.PrivilegedTest(t)

	epTemplate := getEPTemplate(t, ds.d)
	epTemplate.K8sPodName = "foo-pod"
	epTemplate.K8sNamespace = "foo-ns"
	features.GlobalConfig.EnableGoogleMultiNIC = true
	defer func() {
		features.GlobalConfig.EnableGoogleMultiNIC = false
	}()
	ep, _, err := ds.d.createEndpoint(context.TODO(), ds, epTemplate)
	require.NoError(t, err)
	eps := ds.d.endpointManager.LookupEndpointsByContainerID(epTemplate.ContainerID)
	require.Len(t, eps, 1)
	_, code, err := ds.d.createMultiNICEndpoints(context.TODO(), ds, epTemplate, ep)
	require.Equal(t, code, apiEndpoint.PutEndpointIDInvalidCode)
	// Make sure the primary endpoint is also deleted
	require.ErrorContains(t, err, "k8s needs to be enabled for multinic endpoint creation")
	eps = ds.d.endpointManager.LookupEndpointsByContainerID(epTemplate.ContainerID)
	require.Len(t, eps, 0)
}

func (ds *DaemonSuite) TestCreateMultiNICEndpointsNoK8sPodName(t *testing.T) {
	testutils.PrivilegedTest(t)

	features.GlobalConfig.EnableGoogleMultiNIC = true
	defer func() {
		features.GlobalConfig.EnableGoogleMultiNIC = false
	}()
	epTemplate := getEPTemplate(t, ds.d)
	// Create the primary endpoint
	ep, _, err := ds.d.createEndpoint(context.TODO(), ds, epTemplate)
	require.NoError(t, err)
	eps := ds.d.endpointManager.LookupEndpointsByContainerID(epTemplate.ContainerID)
	require.Len(t, eps, 1)

	_, code, err := ds.d.createMultiNICEndpoints(context.TODO(), ds, epTemplate, ep)
	require.Equal(t, code, apiEndpoint.PutEndpointIDInvalidCode)
	// Make sure the primary endpoint is also deleted
	require.ErrorContains(t, err, "k8s namespace and pod name are required to create multinic endpoints")
	eps = ds.d.endpointManager.LookupEndpointsByContainerID(epTemplate.ContainerID)
	require.Len(t, eps, 0)
}

func (ds *DaemonSuite) TestConvertNetworkSpec(t *testing.T) {
	testutils.PrivilegedTest(t)

	intf := convertNetworkSpecToInterface(nil)
	require.Nil(t, intf)

	network := &networkv1alpha1.Network{
		ObjectMeta: metav1.ObjectMeta{
			Name: "network-1",
		},
		Spec: networkv1alpha1.NetworkSpec{
			Routes: []networkv1alpha1.Route{
				{To: "1.1.1.1/20"},
				{To: "2.2.2.2/20"},
			},
			Gateway4: pointer.StringPtr("3.3.3.3"),
		},
	}

	expectedIntf := &networkv1alpha1.NetworkInterface{
		Spec: networkv1alpha1.NetworkInterfaceSpec{
			NetworkName: "network-1",
		},
		Status: networkv1alpha1.NetworkInterfaceStatus{
			Routes: []networkv1alpha1.Route{
				{To: "1.1.1.1/20"},
				{To: "2.2.2.2/20"},
			},
			Gateway4: pointer.StringPtr("3.3.3.3"),
		},
	}

	intf = convertNetworkSpecToInterface(network)
	require.Equal(t, intf, expectedIntf)
}
