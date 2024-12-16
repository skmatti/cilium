package endpointmanager

import (
	"context"
	"testing"

	apiv1 "github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/endpoint"
	endpointid "github.com/cilium/cilium/pkg/endpoint/id"
	"github.com/cilium/cilium/pkg/gke/features"
	multinicep "github.com/cilium/cilium/pkg/gke/multinic/endpoint"
	testidentity "github.com/cilium/cilium/pkg/testutils/identity"
	testipcache "github.com/cilium/cilium/pkg/testutils/ipcache"
	"github.com/stretchr/testify/require"
)

func (s *EndpointManagerSuite) TestLookupMultiNIC(t *testing.T) {
	features.GlobalConfig.EnableGoogleMultiNIC = true
	defer func() {
		features.GlobalConfig.EnableGoogleMultiNIC = false
	}()
	type args struct {
		id string
	}
	type want struct {
		ep  bool
		err error
	}
	tests := []struct {
		name      string
		setupArgs func() args
		setupWant func() want
		cm        apiv1.EndpointChangeRequest
	}{
		{
			name: "endpoint by cilium local ID",
			cm: apiv1.EndpointChangeRequest{
				ID: 1234,
			},
			setupArgs: func() args {
				return args{
					endpointid.NewCiliumID(1234),
				}
			},
			setupWant: func() want {
				return want{
					ep:  true,
					err: nil,
				}
			},
		},
		{
			name: "endpoint by container ID",
			cm: apiv1.EndpointChangeRequest{
				ContainerID: "1234",
			},
			setupArgs: func() args {
				return args{
					endpointid.NewID(endpointid.ContainerIdPrefix, "1234"),
				}
			},
			setupWant: func() want {
				return want{
					ep:  false,
					err: ErrUnsupportedWhenMultiNIC{Prefix: endpointid.ContainerIdPrefix.String()},
				}
			},
		},
		{
			name: "endpoint by docker endpoint ID",
			cm: apiv1.EndpointChangeRequest{
				DockerEndpointID: "1234",
			},
			setupArgs: func() args {
				return args{
					endpointid.NewID(endpointid.DockerEndpointPrefix, "1234"),
				}
			},
			setupWant: func() want {
				return want{
					ep:  false,
					err: ErrUnsupportedWhenMultiNIC{Prefix: endpointid.DockerEndpointPrefix.String()},
				}
			},
		},
		{
			name: "endpoint by container name",
			cm: apiv1.EndpointChangeRequest{
				ContainerName: "foo",
			},
			setupArgs: func() args {
				return args{
					endpointid.NewID(endpointid.ContainerNamePrefix, "foo"),
				}
			},
			setupWant: func() want {
				return want{
					ep:  false,
					err: ErrUnsupportedWhenMultiNIC{Prefix: endpointid.ContainerNamePrefix.String()},
				}
			},
		},
		{
			name: "endpoint by pod name",
			cm: apiv1.EndpointChangeRequest{
				K8sNamespace: "default",
				K8sPodName:   "foo",
			},
			setupArgs: func() args {
				return args{
					endpointid.NewID(endpointid.PodNamePrefix, "default/foo"),
				}
			},
			setupWant: func() want {
				return want{
					ep:  false,
					err: ErrUnsupportedWhenMultiNIC{Prefix: endpointid.PodNamePrefix.String()},
				}
			},
		},
		{
			name: "endpoint by ipv4",
			cm: apiv1.EndpointChangeRequest{
				Addressing: &apiv1.AddressPair{
					IPV4: "127.0.0.1",
				},
			},
			setupArgs: func() args {
				return args{
					endpointid.NewID(endpointid.IPv4Prefix, "127.0.0.1"),
				}
			},
			setupWant: func() want {
				return want{
					ep:  true,
					err: nil,
				}
			},
		},
	}
	for _, tt := range tests {
		ep, err := endpoint.NewEndpointFromChangeModel(context.Background(), s, s, testipcache.NewMockIPCache(), &endpoint.FakeEndpointProxy{}, testidentity.NewMockIdentityAllocator(nil), &tt.cm)
		require.NoError(t, err, "Test Name: %s", tt.name)
		mgr := New(&dummyEpSyncher{}, nil, nil)

		err = mgr.expose(ep)
		require.NoError(t, err, "Test Name: %s", tt.name)

		args := tt.setupArgs()
		want := tt.setupWant()
		got, err := mgr.Lookup(args.id)
		require.Equal(t, want.err, err, "Test Name: %s", tt.name)
		if want.ep {
			require.Equal(t, ep, got, "Test Name: %s", tt.name)
		} else {
			require.Nil(t, got, "Test Name: %s", tt.name)
		}
		mgr.epIDAllocator.reallocatePool(t)
	}
}

func (s *EndpointManagerSuite) TestLookupEndpointsByContainerID(t *testing.T) {
	features.GlobalConfig.EnableGoogleMultiNIC = true
	defer func() {
		features.GlobalConfig.EnableGoogleMultiNIC = false
	}()
	type args struct {
		id string
	}
	type want struct {
		epIds []uint16
	}
	tests := []struct {
		name      string
		setupArgs func() args
		setupWant func() want
		cm        []apiv1.EndpointChangeRequest
	}{
		{
			name: "non-existing container ID",
			setupArgs: func() args {
				return args{
					"foo",
				}
			},
			setupWant: func() want {
				return want{
					epIds: []uint16{},
				}
			},
		},
		{
			name: "existing container ID single endpoint",
			cm: []apiv1.EndpointChangeRequest{
				{
					ContainerID: "foo",
					ID:          1,
				},
			},
			setupArgs: func() args {
				return args{
					"foo",
				}
			},
			setupWant: func() want {
				return want{
					epIds: []uint16{1},
				}
			},
		},
		{
			name: "existing container ID two endpoints",
			cm: []apiv1.EndpointChangeRequest{
				{
					ContainerID: "foo",
					ID:          1,
				},
				{
					ContainerID: "foo",
					ID:          2,
				},
			},
			setupArgs: func() args {
				return args{
					"foo",
				}
			},
			setupWant: func() want {
				return want{
					epIds: []uint16{1, 2},
				}
			},
		},
	}
	for _, tt := range tests {
		mgr := New(&dummyEpSyncher{}, nil, nil)
		for _, req := range tt.cm {
			ep, err := endpoint.NewEndpointFromChangeModel(context.Background(), s, s, testipcache.NewMockIPCache(), &endpoint.FakeEndpointProxy{}, testidentity.NewMockIdentityAllocator(nil), &req)
			require.NoError(t, err, "Test Name: %s", tt.name)
			err = mgr.expose(ep)
			require.NoError(t, err, "Test Name: %s", tt.name)
		}
		args := tt.setupArgs()
		want := tt.setupWant()
		got := mgr.LookupEndpointsByContainerID(args.id)
		gotIds := []uint16{}
		for _, ep := range got {
			gotIds = append(gotIds, ep.ID)
		}
		mgr.RemoveAll(t)
		require.Equal(t, want.epIds, gotIds, "Test Name: %s", tt.name)
	}
}

func (s *EndpointManagerSuite) TestLookupEndpointsByPodName(t *testing.T) {
	features.GlobalConfig.EnableGoogleMultiNIC = true
	defer func() {
		features.GlobalConfig.EnableGoogleMultiNIC = false
	}()
	type args struct {
		id string
	}
	type want struct {
		epIds []uint16
	}
	tests := []struct {
		name      string
		setupArgs func() args
		setupWant func() want
		cm        []apiv1.EndpointChangeRequest
	}{
		{
			name: "non-existing pod name",
			setupArgs: func() args {
				return args{
					"foo",
				}
			},
			setupWant: func() want {
				return want{
					epIds: []uint16{},
				}
			},
		},
		{
			name: "existing container ID single endpoint",
			cm: []apiv1.EndpointChangeRequest{
				{
					K8sNamespace: "default",
					K8sPodName:   "foo",
					ID:           1,
				},
			},
			setupArgs: func() args {
				return args{
					"default/foo",
				}
			},
			setupWant: func() want {
				return want{
					epIds: []uint16{1},
				}
			},
		},
		{
			name: "existing container ID two endpoints",
			cm: []apiv1.EndpointChangeRequest{
				{
					K8sNamespace: "default",
					K8sPodName:   "foo",
					ID:           1,
				},
				{
					K8sNamespace: "default",
					K8sPodName:   "foo",
					ID:           2,
				},
			},
			setupArgs: func() args {
				return args{
					"default/foo",
				}
			},
			setupWant: func() want {
				return want{
					epIds: []uint16{1, 2},
				}
			},
		},
	}
	for _, tt := range tests {
		mgr := New(&dummyEpSyncher{}, nil, nil)
		for _, req := range tt.cm {
			ep, err := endpoint.NewEndpointFromChangeModel(context.Background(), s, s, testipcache.NewMockIPCache(), &endpoint.FakeEndpointProxy{}, testidentity.NewMockIdentityAllocator(nil), &req)
			require.NoError(t, err, "Test Name: %s", tt.name)
			err = mgr.expose(ep)
			require.NoError(t, mgr.expose(ep), "Test Name: %s", tt.name)
		}
		args := tt.setupArgs()
		want := tt.setupWant()
		got := mgr.LookupEndpointsByPodName(args.id)
		gotIds := []uint16{}
		for _, ep := range got {
			gotIds = append(gotIds, ep.ID)
		}
		mgr.RemoveAll(t)
		require.Equal(t, want.epIds, gotIds, "Test Name: %s", tt.name)
	}
}

func (s *EndpointManagerSuite) TestLookupPrimaryEndpointByContainerID(t *testing.T) {
	features.GlobalConfig.EnableGoogleMultiNIC = true
	defer func() {
		features.GlobalConfig.EnableGoogleMultiNIC = false
	}()
	type args struct {
		id string
	}
	type want struct {
		ep *endpoint.Endpoint
	}
	tests := []struct {
		name      string
		setupArgs func() args
		setupWant func() want
		cm        []apiv1.EndpointChangeRequest
	}{
		{
			name: "non-existing pod name",
			setupArgs: func() args {
				return args{
					"foo",
				}
			},
			setupWant: func() want {
				return want{
					ep: nil,
				}
			},
		},
		{
			name: "existing container ID single endpoint",
			cm: []apiv1.EndpointChangeRequest{
				{
					ID:          1,
					ContainerID: "foo",
				},
			},
			setupArgs: func() args {
				return args{
					"foo",
				}
			},
			setupWant: func() want {
				return want{
					ep: &endpoint.Endpoint{ID: 1},
				}
			},
		},
		{
			name: "existing container ID two endpoints",
			cm: []apiv1.EndpointChangeRequest{
				{
					ContainerID: "foo",
					ID:          1,
					DeviceType:  multinicep.EndpointDeviceMACVLAN,
				},
				{
					ContainerID: "foo",
					ID:          2,
				},
			},
			setupArgs: func() args {
				return args{
					"foo",
				}
			},
			setupWant: func() want {
				return want{
					ep: &endpoint.Endpoint{ID: 2},
				}
			},
		},
	}
	for _, tt := range tests {
		mgr := New(&dummyEpSyncher{}, nil, nil)
		for _, req := range tt.cm {
			ep, err := endpoint.NewEndpointFromChangeModel(context.Background(), s, s, testipcache.NewMockIPCache(), &endpoint.FakeEndpointProxy{}, testidentity.NewMockIdentityAllocator(nil), &req)
			require.NoError(t, err, "Test Name: %s", tt.name)
			err = mgr.expose(ep)
			require.NoError(t, mgr.expose(ep), "Test Name: %s", tt.name)
		}
		args := tt.setupArgs()
		want := tt.setupWant()
		got := mgr.LookupPrimaryEndpointByContainerID(args.id)
		if want.ep == nil {
			require.Equal(t, got, "Test Name: %s", tt.name)
		} else {
			require.Equal(t, want.ep.ID, got.ID, "Test Name: %s", tt.name)
		}
		mgr.RemoveAll(t)
	}
}

func (s *EndpointManagerSuite) TestLookupPrimaryEndpointByPodName(t *testing.T) {
	features.GlobalConfig.EnableGoogleMultiNIC = true
	defer func() {
		features.GlobalConfig.EnableGoogleMultiNIC = false
	}()
	var ep1 *endpoint.Endpoint
	var ep2 *endpoint.Endpoint
	mgr := New(&dummyEpSyncher{}, nil, nil)
	type args struct {
		id string
	}
	type want struct {
		ep *endpoint.Endpoint
	}
	tests := []struct {
		name      string
		setupArgs func() args
		setupWant func() want
		cm        []apiv1.EndpointChangeRequest
	}{
		{
			name: "non-existing pod name",
			setupArgs: func() args {
				return args{
					"foo",
				}
			},
			setupWant: func() want {
				return want{
					ep: nil,
				}
			},
		},
		{
			name: "existing container ID single endpoint",
			cm: []apiv1.EndpointChangeRequest{
				{
					ID:           1,
					K8sNamespace: "default",
					K8sPodName:   "foo",
				},
			},
			setupArgs: func() args {
				return args{
					"default/foo",
				}
			},
			setupWant: func() want {
				return want{
					ep: ep1,
				}
			},
		},
		{
			name: "existing container ID two endpoints",
			cm: []apiv1.EndpointChangeRequest{
				{
					K8sNamespace: "default",
					K8sPodName:   "foo",
					DeviceType:   multinicep.EndpointDeviceMACVLAN,
				},
				{
					ID:           1,
					K8sNamespace: "default",
					K8sPodName:   "foo",
				},
			},
			setupArgs: func() args {
				return args{
					"default/foo",
				}
			},
			setupWant: func() want {
				return want{
					ep: ep2,
				}
			},
		},
	}
	for _, tt := range tests {
		args := tt.setupArgs()
		want := tt.setupWant()
		got := mgr.LookupPrimaryEndpointByPodName(args.id)
		require.Equal(t, want.ep, got, "Test Name: %s", tt.name)
	}
}

func (s *EndpointManagerSuite) TestUpdateReferencesMultiNIC(t *testing.T) {
	features.GlobalConfig.EnableGoogleMultiNIC = true
	defer func() {
		features.GlobalConfig.EnableGoogleMultiNIC = false
	}()
	var ep *endpoint.Endpoint
	var err error
	type args struct {
		ep *endpoint.Endpoint
	}
	type want struct {
		ep *endpoint.Endpoint
	}
	tests := []struct {
		name      string
		setupArgs func() args
		setupWant func() want
		cm        apiv1.EndpointChangeRequest
	}{
		{
			name: "Updating all references",
			cm: apiv1.EndpointChangeRequest{
				ID:               1,
				ContainerID:      "container",
				DockerEndpointID: "dockerendpointID",
				K8sNamespace:     "default",
				K8sPodName:       "foo",
				ContainerName:    "containername",
				Addressing: &apiv1.AddressPair{
					IPV4: "127.0.0.1",
				},
			},
			setupArgs: func() args {
				return args{
					ep: ep,
				}
			},
			setupWant: func() want {
				return want{
					ep: ep,
				}
			},
		},
	}
	for _, tt := range tests {
		ep, err = endpoint.NewEndpointFromChangeModel(context.Background(), s, s, testipcache.NewMockIPCache(), &endpoint.FakeEndpointProxy{}, testidentity.NewMockIdentityAllocator(nil), &tt.cm)
		require.NoError(t, err, "Test Name: %s", tt.name)
		mgr := New(&dummyEpSyncher{}, nil, nil)

		err = mgr.expose(ep)
		require.NoError(t, err, "Test Name: %s", tt.name)
		args := tt.setupArgs()
		want := tt.setupWant()
		mgr.updateReferencesLocked(args.ep, args.ep.Identifiers())

		ep = mgr.lookupContainerID(want.ep.GetContainerID())
		require.Nil(t, ep, "Test Name: %s", tt.name)

		ep = mgr.lookupDockerEndpoint(want.ep.GetDockerEndpointID())
		require.Nil(t, ep, "Test Name: %s", tt.name)

		ep = mgr.LookupIPv4(want.ep.IPv4.String())
		require.Equal(t, want.ep.GetIPv4Address(), ep.GetIPv4Address(), "Test Name: %s", tt.name)

		ep = mgr.lookupDockerContainerName(want.ep.GetContainerName())
		require.Nil(t, ep, "Test Name: %s", tt.name)

		ep = mgr.LookupPrimaryEndpointByPodName(want.ep.GetK8sNamespaceAndPodName())
		require.Equal(t, want.ep.GetK8sPodName(), ep.GetK8sPodName(), "Test Name: %s", tt.name)
		eps := mgr.LookupEndpointsByContainerID(want.ep.GetContainerID())
		require.Equal(t, want.ep.GetContainerID(), eps[0].GetContainerID(), "Test Name: %s", tt.name)
		eps = mgr.LookupEndpointsByPodName(want.ep.GetK8sNamespaceAndPodName())
		require.Equal(t, want.ep.GetK8sPodName(), eps[0].GetK8sPodName(), "Test Name: %s", tt.name)
	}
}

func (s *EndpointManagerSuite) TestRemoveMultiNIC(t *testing.T) {
	features.GlobalConfig.EnableGoogleMultiNIC = true
	defer func() {
		features.GlobalConfig.EnableGoogleMultiNIC = false
	}()
	tests := []struct {
		name string
		cm   apiv1.EndpointChangeRequest
	}{
		{
			name: "Updating all references",
			cm: apiv1.EndpointChangeRequest{
				ID:          1,
				ContainerID: "foo",
				K8sPodName:  "bar",
			},
		},
	}
	for _, tt := range tests {
		ep, err := endpoint.NewEndpointFromChangeModel(context.Background(), s, s, testipcache.NewMockIPCache(), &endpoint.FakeEndpointProxy{}, testidentity.NewMockIdentityAllocator(nil), &tt.cm)
		require.NoError(t, err, "Test Name: %s", tt.name)
		mgr := New(&dummyEpSyncher{}, nil, nil)

		err = mgr.expose(ep)
		require.NoError(t, err, "Test Name: %s", tt.name)

		mgr.RemoveAll(t)
		require.Equal(t, 0, len(mgr.endpoints), "Test Name: %s", tt.name)
		require.Equal(t, 0, len(mgr.endpointsAux), "Test Name: %s", tt.name)
		require.Equal(t, 0, len(mgr.endpointsMultiNIC), "Test Name: %s", tt.name)
	}
}
