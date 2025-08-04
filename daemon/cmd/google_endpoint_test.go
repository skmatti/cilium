package cmd

import (
	"context"
	"errors"
	"testing"

	networkv1 "github.com/GoogleCloudPlatform/gke-networking-api/apis/network/v1"
	apiEndpoint "github.com/cilium/cilium/api/v1/server/restapi/endpoint"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/endpointmanager"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/k8s/watchers"
	"github.com/stretchr/testify/require"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/utils/pointer"

	ipamv1alpha1 "gke-internal.googlesource.com/anthos-networking/ipam-controller/api/v1alpha1"
)

func TestCreateEndpointQueueConsul(t *testing.T) {
	ds := setupDaemonConsulSuite(t)
	ds.testCreateEndpointQueue(t)
}

func TestCreateEndpointQueueEtcd(t *testing.T) {
	ds := setupDaemonEtcdSuite(t)
	ds.testCreateEndpointQueue(t)
}

func (ds *DaemonSuite) testCreateEndpointQueue(t *testing.T) {
	epTemplate := getEPTemplate(t, ds.d)
	epTemplate.K8sPodName = "foo-pod"
	epTemplate.K8sNamespace = "foo-ns"
	// Create the primary endpoint
	err := ds.d.CreateEndpoint(context.TODO(), epTemplate)
	require.Empty(t, err)
}

// multinetworkingEnabledDaemon enables multinetworking for the daemon.
// The returned function restores the original daemon state.
// Note: this function is not concurrent safe (i.e. test cannot t.Parallel())
func multinetworkingEnabledDaemon(d *Daemon) func() {
	oldMgr := d.endpointManager
	mgr := endpointmanager.New(&dummyEpSyncher{}, nil, nil)
	mgr.SetEnableGoogleMultiNIC(true)
	d.endpointManager = mgr
	d.googleMultiNICEnabled = true
	return func() {
		d.googleMultiNICEnabled = false
		d.endpointManager = oldMgr
	}
}

func TestCreateMultiNICEndpointsNoK8sEnabledConsul(t *testing.T) {
	ds := setupDaemonConsulSuite(t)
	ds.testCreateMultiNICEndpointsNoK8sEnabled(t)
}

func TestCreateMultiNICEndpointsNoK8sEnabledEtcd(t *testing.T) {
	ds := setupDaemonEtcdSuite(t)
	ds.testCreateMultiNICEndpointsNoK8sEnabled(t)
}

func (ds *DaemonSuite) testCreateMultiNICEndpointsNoK8sEnabled(t *testing.T) {
	epTemplate := getEPTemplate(t, ds.d)
	epTemplate.K8sPodName = "foo-pod"
	epTemplate.K8sNamespace = "foo-ns"
	revert := multinetworkingEnabledDaemon(ds.d)
	defer revert()
	ep, _, err := ds.d.createEndpoint(context.TODO(), ds, epTemplate)
	require.NoError(t, err)
	eps := ds.d.endpointManager.GetEndpointsByContainerID(epTemplate.ContainerID)
	require.Len(t, eps, 1)

	multiNICCleanupWaitCh := make(chan struct{})
	defer close(multiNICCleanupWaitCh)
	_, code, err := ds.d.createMultiNICEndpoints(context.TODO(), multiNICCleanupWaitCh, ds, epTemplate, ep)
	require.Equal(t, code, apiEndpoint.PutEndpointIDInvalidCode)
	// Make sure the primary endpoint is also deleted
	require.ErrorContains(t, err, "k8s needs to be enabled for multinic endpoint creation")
	eps = ds.d.endpointManager.GetEndpointsByContainerID(epTemplate.ContainerID)
	require.Len(t, eps, 0)
}

func TestCreateMultiNICEndpointsNoK8sPodNameConsul(t *testing.T) {
	ds := setupDaemonConsulSuite(t)
	ds.testCreateMultiNICEndpointsNoK8sPodName(t)
}

func TestCreateMultiNICEndpointsNoK8sPodNameEtcd(t *testing.T) {
	ds := setupDaemonEtcdSuite(t)
	ds.testCreateMultiNICEndpointsNoK8sPodName(t)
}

func (ds *DaemonSuite) testCreateMultiNICEndpointsNoK8sPodName(t *testing.T) {
	ds.d.multinicClient = &mockMultiNICClient{}
	revert := multinetworkingEnabledDaemon(ds.d)
	defer revert()
	epTemplate := getEPTemplate(t, ds.d)
	// Create the primary endpoint
	ep, _, err := ds.d.createEndpoint(context.TODO(), ds, epTemplate)
	require.NoError(t, err)
	eps := ds.d.endpointManager.GetEndpointsByContainerID(epTemplate.ContainerID)
	require.Len(t, eps, 1)

	multiNICCleanupWaitCh := make(chan struct{})
	defer close(multiNICCleanupWaitCh)
	_, code, err := ds.d.createMultiNICEndpoints(context.TODO(), multiNICCleanupWaitCh, ds, epTemplate, ep)
	require.Equal(t, code, apiEndpoint.PutEndpointIDInvalidCode)
	// Make sure the primary endpoint is also deleted
	require.ErrorContains(t, err, "k8s namespace and pod name are required to create multinic endpoints")
	eps = ds.d.endpointManager.GetEndpointsByContainerID(epTemplate.ContainerID)
	require.Len(t, eps, 0)
}

func TestConvertNetworkSpec(t *testing.T) {
	intf := convertNetworkSpecToInterface(nil)
	require.Nil(t, intf)

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
	require.Equal(t, intf, expectedIntf)
}

type fakeEndpointMetadataFetcher struct {
	k8sWatcher *watchers.K8sWatcher
}

func (f *fakeEndpointMetadataFetcher) Fetch(nsName, podName string) (*slim_corev1.Namespace, *slim_corev1.Pod, error) {
	return nil, nil, errors.New("pod not found")
}

func TestDeleteEndpointsMissingPodConsul(t *testing.T) {
	ds := setupDaemonConsulSuite(t)
	ds.testDeleteEndpointsMissingPod(t)
}

func TestDeleteEndpointsMissingPodEtcd(t *testing.T) {
	ds := setupDaemonEtcdSuite(t)
	ds.testDeleteEndpointsMissingPod(t)
}

func (ds *DaemonSuite) testDeleteEndpointsMissingPod(t *testing.T) {
	epTemplate := getEPTemplate(t, ds.d)
	epTemplate.K8sPodName = "foo-pod"
	revert := multinetworkingEnabledDaemon(ds.d)
	defer revert()
	ep, _, err := ds.d.createEndpoint(context.TODO(), ds, epTemplate)
	require.NoError(t, err)
	eps := ds.d.endpointManager.GetEndpointsByContainerID(epTemplate.ContainerID)
	require.Len(t, eps, 1)
	ds.d.endpointMetadataFetcher = &fakeEndpointMetadataFetcher{&watchers.K8sWatcher{}}
	_, err = ds.d.deleteEndpoints(context.TODO(), []*endpoint.Endpoint{ep})
	require.NoError(t, err)
	// Make sure the primary endpoint is also deleted
	eps = ds.d.endpointManager.GetEndpointsByContainerID(epTemplate.ContainerID)
	require.Len(t, eps, 0)
}

func TestDefaultNetworkConsul(t *testing.T) {
	ds := setupDaemonConsulSuite(t)
	ds.testDefaultNetwork(t)
}

func TestDefaultNetworkEtcd(t *testing.T) {
	ds := setupDaemonEtcdSuite(t)
	ds.testDefaultNetwork(t)
}

func (ds *DaemonSuite) testDefaultNetwork(t *testing.T) {
	ds.d.multinicClient = &mockMultiNICClient{}

	var networkCR *networkv1.Network
	var err error

	// Both default and pod-network don't exist.
	defaultExist, podNetworkExist = false, false
	networkCR, err = ds.d.defaultNetwork(context.TODO())
	require.ErrorContains(t, err, "default network \"pod-network\":")

	defaultExist, podNetworkExist = true, true
	networkCR, err = ds.d.defaultNetwork(context.TODO())
	require.NoError(t, err)
	require.Equal(t, networkCR.Name, "default")

	defaultExist, podNetworkExist = true, false
	networkCR, err = ds.d.defaultNetwork(context.TODO())
	require.NoError(t, err)
	require.Equal(t, networkCR.Name, "default")

	defaultExist, podNetworkExist = false, true
	networkCR, err = ds.d.defaultNetwork(context.TODO())
	require.NoError(t, err)
	require.Equal(t, networkCR.Name, "pod-network")
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
func (m *mockMultiNICClient) PatchNetworkInterfaceAnnotations(ctx context.Context, _ *networkv1.NetworkInterface) error {
	return nil
}
func (m *mockMultiNICClient) PatchNetworkInterfaceStatus(ctx context.Context, obj *networkv1.NetworkInterface) error {
	return nil
}
func (m *mockMultiNICClient) PatchPodAnnotation(ctx context.Context, obj *v1.Pod, anno map[string]string) error {
	return nil
}
func (m *mockMultiNICClient) GetGKENetworkParamSet(ctx context.Context, ref *networkv1.NetworkParametersReference) (*networkv1.GKENetworkParamSet, error) {
	return nil, nil
}

func (m *mockMultiNICClient) GetClusterCIDRConfigForNetwork(ctx context.Context, nwName string) (*ipamv1alpha1.ClusterCIDRConfig, error) {
	return nil, nil
}

func (c *mockMultiNICClient) GetNetworkDevices(ctx context.Context) ([]string, error) {
	return nil, nil
}
