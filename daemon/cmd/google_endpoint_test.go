//go:build !privileged_tests && integration_tests
// +build !privileged_tests,integration_tests

package cmd

import (
	"context"
	"strings"

	apiEndpoint "github.com/cilium/cilium/api/v1/server/restapi/endpoint"
	"github.com/cilium/cilium/pkg/checker"
	"github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/option"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	networkv1 "k8s.io/cloud-provider-gcp/crd/apis/network/v1"
	"k8s.io/utils/pointer"

	. "gopkg.in/check.v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func (ds *DaemonSuite) TestCreateMultiNICEndpointsNoK8sEnabled(c *C) {
	ds.d.multinicClient = &mockMultiNICClient{}
	option.Config.EnableGoogleMultiNIC = true
	defer func() {
		option.Config.EnableGoogleMultiNIC = false
	}()
	epTemplate := getEPTemplate(c, ds.d)
	epTemplate.K8sPodName = "foo-pod"
	epTemplate.K8sNamespace = "foo-ns"
	// Create the primary endpoint
	ep, _, err := ds.d.createEndpoint(context.TODO(), ds, epTemplate)
	c.Assert(err, IsNil)
	eps := ds.d.endpointManager.LookupEndpointsByContainerID(epTemplate.ContainerID)
	c.Assert(eps, HasLen, 1)

	_, code, err := ds.d.createMultiNICEndpoints(context.TODO(), ds, epTemplate, ep)
	c.Assert(code, Equals, apiEndpoint.PutEndpointIDInvalidCode)
	// Make sure the primary endpoint is also deleted
	c.Assert(err, ErrorMatches, "k8s needs to be enabled for multinic endpoint creation")
	eps = ds.d.endpointManager.LookupEndpointsByContainerID(epTemplate.ContainerID)
	c.Assert(eps, HasLen, 0)
}

func (ds *DaemonSuite) TestCreateMultiNICEndpointsNoK8sPodName(c *C) {
	ds.d.multinicClient = &mockMultiNICClient{}
	option.Config.EnableGoogleMultiNIC = true
	defer func() {
		option.Config.EnableGoogleMultiNIC = false
	}()
	epTemplate := getEPTemplate(c, ds.d)
	// Create the primary endpoint
	ep, _, err := ds.d.createEndpoint(context.TODO(), ds, epTemplate)
	c.Assert(err, IsNil)
	eps := ds.d.endpointManager.LookupEndpointsByContainerID(epTemplate.ContainerID)
	c.Assert(eps, HasLen, 1)

	_, code, err := ds.d.createMultiNICEndpoints(context.TODO(), ds, epTemplate, ep)
	c.Assert(code, Equals, apiEndpoint.PutEndpointIDInvalidCode)
	// Make sure the primary endpoint is also deleted
	c.Assert(err, ErrorMatches, "k8s namespace and pod name are required to create multinic endpoints")
	eps = ds.d.endpointManager.LookupEndpointsByContainerID(epTemplate.ContainerID)
	c.Assert(eps, HasLen, 0)
}

func (ds *DaemonSuite) TestConvertNetworkSpec(c *C) {
	intf := convertNetworkSpecToInterface(nil)
	c.Assert(intf, IsNil)

	network := &networkv1.Network{
		ObjectMeta: metav1.ObjectMeta{
			Name: "network-1",
		},
		Spec: networkv1.NetworkSpec{
			Routes: []networkv1.Route{
				{To: "1.1.1.1/20"},
				{To: "2.2.2.2/20"},
			},
			Gateway4: pointer.StringPtr("3.3.3.3"),
		},
	}

	expectedIntf := &networkv1.NetworkInterface{
		Spec: networkv1.NetworkInterfaceSpec{
			NetworkName: "network-1",
		},
		Status: networkv1.NetworkInterfaceStatus{
			Routes: []networkv1.Route{
				{To: "1.1.1.1/20"},
				{To: "2.2.2.2/20"},
			},
			Gateway4: pointer.StringPtr("3.3.3.3"),
		},
	}

	intf = convertNetworkSpecToInterface(network)
	c.Assert(intf, checker.DeepEquals, expectedIntf)
}

func (ds *DaemonSuite) TestDefaultNetwork(c *C) {
	ds.d.multinicClient = &mockMultiNICClient{}

	var networkCR *networkv1.Network
	var err error

	// Both default and pod-network don't exist.
	defaultExist, podNetworkExist = false, false
	networkCR, err = ds.d.defaultNetwork(context.TODO())
	c.Assert(strings.Contains(err.Error(), "default network \"pod-network\":"), Equals, true)

	defaultExist, podNetworkExist = true, true
	networkCR, err = ds.d.defaultNetwork(context.TODO())
	c.Assert(err, IsNil)
	c.Assert(networkCR.Name, Equals, "default")

	defaultExist, podNetworkExist = true, false
	networkCR, err = ds.d.defaultNetwork(context.TODO())
	c.Assert(err, IsNil)
	c.Assert(networkCR.Name, Equals, "default")

	defaultExist, podNetworkExist = false, true
	networkCR, err = ds.d.defaultNetwork(context.TODO())
	c.Assert(err, IsNil)
	c.Assert(networkCR.Name, Equals, "pod-network")
}

var defaultExist, podNetworkExist bool

type mockMultiNICClient struct{}

func (m *mockMultiNICClient) GetNetworkInterface(ctx context.Context, name, namespace string) (*networkv1.NetworkInterface, error) {
	return nil, nil
}

func (m *mockMultiNICClient) GetNetwork(ctx context.Context, name string) (*networkv1.Network, error) {
	if defaultExist && name == networkv1.DefaultPodNetworkName {
		return &networkv1.Network{
			ObjectMeta: metav1.ObjectMeta{
				Name: "default",
			},
		}, nil
	}
	if podNetworkExist && name == networkv1.DefaultNetworkName {
		return &networkv1.Network{
			ObjectMeta: metav1.ObjectMeta{
				Name: "pod-network",
			},
		}, nil
	}
	return nil, apierrors.NewNotFound(schema.GroupResource{}, name)
}

func (m *mockMultiNICClient) ListNetworks(ctx context.Context) ([]networkv1.Network, error) {
	return []networkv1.Network{}, nil
}
func (m *mockMultiNICClient) ListNetworkInterfaces(ctx context.Context, opts ...client.ListOption) (*networkv1.NetworkInterfaceList, error) {
	return nil, nil
}
func (m *mockMultiNICClient) PatchNetworkInterface(ctx context.Context, _, _ *networkv1.NetworkInterface) error {
	return nil
}
func (m *mockMultiNICClient) PatchNetworkInterfaceStatus(ctx context.Context, obj *networkv1.NetworkInterface) error {
	return nil
}
func (m *mockMultiNICClient) CreateNetworkInterface(ctx context.Context, obj *networkv1.NetworkInterface) error {
	return nil
}
func (m *mockMultiNICClient) DeleteNetworkInterface(ctx context.Context, obj *networkv1.NetworkInterface) error {
	return nil
}
func (m *mockMultiNICClient) SetPodIPsAnnotation(ctx context.Context, pod *v1.Pod, podIPs *networkv1.PodIPsAnnotation) error {
	return nil
}
func (m *mockMultiNICClient) GetNetworkParamObject(ctx context.Context, ref *networkv1.NetworkParametersReference) (client.Object, error) {
	return nil, nil
}
