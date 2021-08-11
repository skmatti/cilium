package endpointmanager

import (
	"context"

	apiv1 "github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/checker"
	"github.com/cilium/cilium/pkg/endpoint"
	endpointid "github.com/cilium/cilium/pkg/endpoint/id"
	"github.com/cilium/cilium/pkg/endpointmanager/idallocator"
	"github.com/cilium/cilium/pkg/option"
	testidentity "github.com/cilium/cilium/pkg/testutils/identity"
	testipcache "github.com/cilium/cilium/pkg/testutils/ipcache"

	. "gopkg.in/check.v1"
)

func (s *EndpointManagerSuite) TestLookupMultiNIC(c *C) {
	option.Config.EnableGoogleMultiNIC = true
	defer func() {
		option.Config.EnableGoogleMultiNIC = false
	}()
	type args struct {
		id string
	}
	type want struct {
		ep       bool
		err      error
		errCheck Checker
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
					ep:       true,
					err:      nil,
					errCheck: Equals,
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
					ep:       false,
					err:      ErrUnsupportedWhenMultiNIC{Prefix: endpointid.ContainerIdPrefix.String()},
					errCheck: Equals,
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
					ep:       false,
					err:      ErrUnsupportedWhenMultiNIC{Prefix: endpointid.DockerEndpointPrefix.String()},
					errCheck: Equals,
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
					ep:       false,
					err:      ErrUnsupportedWhenMultiNIC{Prefix: endpointid.ContainerNamePrefix.String()},
					errCheck: Equals,
				}
			},
		},
		{
			name: "endpoint by pod name",
			cm: apiv1.EndpointChangeRequest{
				K8sPodName:   "foo",
				K8sNamespace: "default",
			},
			setupArgs: func() args {
				return args{
					endpointid.NewID(endpointid.PodNamePrefix, "default/foo"),
				}
			},
			setupWant: func() want {
				return want{
					ep:       false,
					err:      ErrUnsupportedWhenMultiNIC{Prefix: endpointid.PodNamePrefix.String()},
					errCheck: Equals,
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
					ep:       true,
					err:      nil,
					errCheck: Equals,
				}
			},
		},
	}
	for _, tt := range tests {
		ep, err := endpoint.NewEndpointFromChangeModel(context.Background(), s, s, testipcache.NewMockIPCache(), &endpoint.FakeEndpointProxy{}, testidentity.NewMockIdentityAllocator(nil), &tt.cm)
		c.Assert(err, IsNil, Commentf("Test Name: %s", tt.name))
		mgr := NewEndpointManager(&dummyEpSyncher{})

		err = mgr.expose(ep)
		c.Assert(err, IsNil, Commentf("Test Name: %s", tt.name))

		args := tt.setupArgs()
		want := tt.setupWant()
		got, err := mgr.Lookup(args.id)
		c.Assert(err, want.errCheck, want.err, Commentf("Test Name: %s", tt.name))
		if want.ep {
			c.Assert(got, checker.DeepEquals, ep, Commentf("Test Name: %s", tt.name))
		} else {
			c.Assert(got, IsNil, Commentf("Test Name: %s", tt.name))
		}
		idallocator.ReallocatePool()
	}
}

func (s *EndpointManagerSuite) TestLookupEndpointsByContainerID(c *C) {
	option.Config.EnableGoogleMultiNIC = true
	defer func() {
		option.Config.EnableGoogleMultiNIC = false
	}()

	ctx := context.Background()
	mgr := NewEndpointManager(&dummyEpSyncher{})
	ipc := testipcache.NewMockIPCache()

	ep1, err := endpoint.NewEndpointFromChangeModel(ctx, s, s, ipc, &endpoint.FakeEndpointProxy{}, testidentity.NewMockIdentityAllocator(nil), &apiv1.EndpointChangeRequest{
		ID:          1,
		ContainerID: "foo",
		DeviceType:  endpoint.EndpointDeviceMACVLAN,
	})
	c.Assert(err, IsNil)
	mgr.expose(ep1)

	ep2, err := endpoint.NewEndpointFromChangeModel(ctx, s, s, ipc, &endpoint.FakeEndpointProxy{}, testidentity.NewMockIdentityAllocator(nil), &apiv1.EndpointChangeRequest{
		ID:          2,
		ContainerID: "foo",
	})
	c.Assert(err, IsNil)
	mgr.expose(ep2)

	ep3, err := endpoint.NewEndpointFromChangeModel(ctx, s, s, ipc, &endpoint.FakeEndpointProxy{}, testidentity.NewMockIdentityAllocator(nil), &apiv1.EndpointChangeRequest{
		ID:          3,
		ContainerID: "bar",
	})
	c.Assert(err, IsNil)
	mgr.expose(ep3)

	type args struct {
		id string
	}
	type want struct {
		eps       []*endpoint.Endpoint
		primaryEp *endpoint.Endpoint
	}
	tests := []struct {
		name      string
		setupArgs func() args
		setupWant func() want
	}{
		{
			name: "non-existing container ID",
			setupArgs: func() args {
				return args{
					"boo",
				}
			},
			setupWant: func() want {
				return want{
					eps:       nil,
					primaryEp: nil,
				}
			},
		},
		{
			name: "existing container ID single endpoint",
			setupArgs: func() args {
				return args{
					"bar",
				}
			},
			setupWant: func() want {
				return want{
					eps:       []*endpoint.Endpoint{ep3},
					primaryEp: ep3,
				}
			},
		},
		{
			name: "existing container ID two endpoints",
			setupArgs: func() args {
				return args{
					"foo",
				}
			},
			setupWant: func() want {
				return want{
					eps:       []*endpoint.Endpoint{ep1, ep2},
					primaryEp: ep2,
				}
			},
		},
	}
	for _, tt := range tests {
		args := tt.setupArgs()
		want := tt.setupWant()

		gotEps := mgr.LookupEndpointsByContainerID(args.id)
		c.Assert(gotEps, checker.DeepEquals, want.eps, Commentf("Test Name: %s", tt.name))

		gotPrimaryEp := mgr.LookupPrimaryEndpointByContainerID(args.id)
		c.Assert(gotPrimaryEp, checker.DeepEquals, want.primaryEp, Commentf("Test Name: %s", tt.name))
	}
}

func (s *EndpointManagerSuite) TestLookupEndpointsByPodName(c *C) {
	option.Config.EnableGoogleMultiNIC = true
	defer func() {
		option.Config.EnableGoogleMultiNIC = false
	}()

	ctx := context.Background()
	mgr := NewEndpointManager(&dummyEpSyncher{})
	ipc := testipcache.NewMockIPCache()

	ep1, err := endpoint.NewEndpointFromChangeModel(ctx, s, s, ipc, &endpoint.FakeEndpointProxy{}, testidentity.NewMockIdentityAllocator(nil), &apiv1.EndpointChangeRequest{
		ID:           1,
		K8sPodName:   "foo",
		K8sNamespace: "default",
		DeviceType:   endpoint.EndpointDeviceVETH,
	})
	c.Assert(err, IsNil)
	mgr.expose(ep1)

	ep2, err := endpoint.NewEndpointFromChangeModel(ctx, s, s, ipc, &endpoint.FakeEndpointProxy{}, testidentity.NewMockIdentityAllocator(nil), &apiv1.EndpointChangeRequest{
		ID:           2,
		K8sPodName:   "foo",
		K8sNamespace: "default",
	})
	c.Assert(err, IsNil)
	mgr.expose(ep2)

	ep3, err := endpoint.NewEndpointFromChangeModel(ctx, s, s, ipc, &endpoint.FakeEndpointProxy{}, testidentity.NewMockIdentityAllocator(nil), &apiv1.EndpointChangeRequest{
		ID:           3,
		K8sPodName:   "bar",
		K8sNamespace: "default",
	})
	c.Assert(err, IsNil)
	mgr.expose(ep3)

	type args struct {
		id string
	}
	type want struct {
		eps       []*endpoint.Endpoint
		primaryEp *endpoint.Endpoint
	}
	tests := []struct {
		name      string
		setupArgs func() args
		setupWant func() want
	}{
		{
			name: "non-existing pod name",
			setupArgs: func() args {
				return args{
					"boo",
				}
			},
			setupWant: func() want {
				return want{
					eps:       nil,
					primaryEp: nil,
				}
			},
		},
		{
			name: "existing container ID single endpoint",
			setupArgs: func() args {
				return args{
					"default/bar",
				}
			},
			setupWant: func() want {
				return want{
					eps:       []*endpoint.Endpoint{ep3},
					primaryEp: ep3,
				}
			},
		},
		{
			name: "existing container ID two endpoints",
			setupArgs: func() args {
				return args{
					"default/foo",
				}
			},
			setupWant: func() want {
				return want{
					eps:       []*endpoint.Endpoint{ep1, ep2},
					primaryEp: ep2,
				}
			},
		},
	}
	for _, tt := range tests {
		args := tt.setupArgs()
		want := tt.setupWant()

		gotEps := mgr.LookupEndpointsByPodName(args.id)
		c.Assert(gotEps, checker.DeepEquals, want.eps, Commentf("Test Name: %s", tt.name))

		gotPrimaryEp := mgr.LookupPrimaryEndpointByPodName(args.id)
		c.Assert(gotPrimaryEp, checker.DeepEquals, want.primaryEp, Commentf("Test Name: %s", tt.name))
	}
}

func (s *EndpointManagerSuite) TestUpdateReferencesMultiNIC(c *C) {
	option.Config.EnableGoogleMultiNIC = true
	defer func() {
		option.Config.EnableGoogleMultiNIC = false
	}()

	var ep *endpoint.Endpoint
	type want struct {
		ep *endpoint.Endpoint
	}
	tests := []struct {
		name      string
		cm        apiv1.EndpointChangeRequest
		setupWant func() want
	}{
		{
			name: "Updating all references",
			cm: apiv1.EndpointChangeRequest{
				K8sNamespace:     "default",
				K8sPodName:       "foo",
				ContainerID:      "container",
				DockerEndpointID: "dockerendpointID",
				Addressing: &apiv1.AddressPair{
					IPV4: "127.0.0.1",
				},
				ContainerName: "containername",
			},
			setupWant: func() want {
				return want{
					ep: ep,
				}
			},
		},
	}
	for _, tt := range tests {
		var err error
		ep, err = endpoint.NewEndpointFromChangeModel(context.Background(), s, s, testipcache.NewMockIPCache(), &endpoint.FakeEndpointProxy{}, testidentity.NewMockIdentityAllocator(nil), &tt.cm)
		c.Assert(err, IsNil, Commentf("Test Name: %s", tt.name))
		mgr := NewEndpointManager(&dummyEpSyncher{})

		err = mgr.expose(ep)
		c.Assert(err, IsNil, Commentf("Test Name: %s", tt.name))
		want := tt.setupWant()
		mgr.updateReferencesLocked(ep, ep.IdentifiersLocked())

		ep = mgr.LookupContainerID(want.ep.GetContainerID())
		c.Assert(ep, IsNil, Commentf("Test Name: %s", tt.name))

		ep = mgr.lookupDockerEndpoint(want.ep.GetDockerEndpointID())
		c.Assert(ep, IsNil, Commentf("Test Name: %s", tt.name))

		ep = mgr.LookupIPv4(want.ep.IPv4.String())
		c.Assert(ep, checker.DeepEquals, want.ep, Commentf("Test Name: %s", tt.name))

		ep = mgr.lookupDockerContainerName(want.ep.GetContainerName())
		c.Assert(ep, IsNil, Commentf("Test Name: %s", tt.name))

		ep = mgr.LookupPodName(want.ep.GetK8sNamespaceAndPodName())
		c.Assert(ep, IsNil, Commentf("Test Name: %s", tt.name))

		ep = mgr.LookupPrimaryEndpointByPodName(want.ep.GetK8sNamespaceAndPodName())
		c.Assert(ep, checker.DeepEquals, want.ep, Commentf("Test Name: %s", tt.name))
		eps := mgr.LookupEndpointsByContainerID(want.ep.GetContainerID())
		c.Assert(eps, checker.DeepEquals, []*endpoint.Endpoint{want.ep}, Commentf("Test Name: %s", tt.name))
		eps = mgr.LookupEndpointsByPodName(want.ep.GetK8sNamespaceAndPodName())
		c.Assert(eps, checker.DeepEquals, []*endpoint.Endpoint{want.ep}, Commentf("Test Name: %s", tt.name))
	}
}

func (s *EndpointManagerSuite) TestRemoveMultiNIC(c *C) {
	option.Config.EnableGoogleMultiNIC = true
	defer func() {
		option.Config.EnableGoogleMultiNIC = false
	}()

	mgr := NewEndpointManager(&dummyEpSyncher{})
	ep, err := endpoint.NewEndpointFromChangeModel(context.Background(), s, s, testipcache.NewMockIPCache(), &endpoint.FakeEndpointProxy{}, testidentity.NewMockIdentityAllocator(nil), &apiv1.EndpointChangeRequest{
		ContainerID:  "foo",
		K8sPodName:   "bar",
		K8sNamespace: "default",
	})
	c.Assert(err, IsNil)
	mgr.expose(ep)
	mgr.RemoveAll()
	c.Assert(len(mgr.endpoints), Equals, 0)
	c.Assert(len(mgr.endpointsAux), Equals, 0)
	c.Assert(len(mgr.endpointsMultiNIC), Equals, 0)
}
