//go:build !privileged_tests
// +build !privileged_tests

package endpointmanager

import (
	"github.com/cilium/cilium/pkg/addressing"
	"github.com/cilium/cilium/pkg/checker"
	"github.com/cilium/cilium/pkg/endpoint"
	endpointid "github.com/cilium/cilium/pkg/endpoint/id"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/testutils/allocator"

	. "gopkg.in/check.v1"
)

func (s *EndpointManagerSuite) TestLookupMultiNIC(c *C) {
	option.Config.EnableGoogleMultiNIC = true
	defer func() {
		option.Config.EnableGoogleMultiNIC = false
	}()

	ep := endpoint.NewEndpointWithState(s, &endpoint.FakeEndpointProxy{}, &allocator.FakeIdentityAllocator{}, 10, endpoint.StateReady)
	mgr := NewEndpointManager(&dummyEpSyncher{})
	type args struct {
		id string
	}
	type want struct {
		ep       *endpoint.Endpoint
		err      error
		errCheck Checker
	}
	tests := []struct {
		name        string
		setupArgs   func() args
		setupWant   func() want
		preTestRun  func()
		postTestRun func()
	}{
		{
			name: "endpoint by cilium local ID",
			preTestRun: func() {
				ep.ID = 1234
				mgr.expose(ep)
			},
			setupArgs: func() args {
				return args{
					endpointid.NewCiliumID(1234),
				}
			},
			setupWant: func() want {
				return want{
					ep:       ep,
					err:      nil,
					errCheck: Equals,
				}
			},
			postTestRun: func() {
				mgr.WaitEndpointRemoved(ep)
				ep = endpoint.NewEndpointWithState(s, &endpoint.FakeEndpointProxy{}, &allocator.FakeIdentityAllocator{}, 10, endpoint.StateReady)
				ep.ID = 0
			},
		},
		{
			name: "endpoint by container ID",
			preTestRun: func() {
				ep.SetContainerID("1234")
				mgr.expose(ep)
			},
			setupArgs: func() args {
				return args{
					endpointid.NewID(endpointid.ContainerIdPrefix, "1234"),
				}
			},
			setupWant: func() want {
				return want{
					ep:       nil,
					err:      ErrUnsupportedWhenMultiNIC{Prefix: endpointid.ContainerIdPrefix.String()},
					errCheck: Equals,
				}
			},
			postTestRun: func() {
				mgr.WaitEndpointRemoved(ep)
				ep = endpoint.NewEndpointWithState(s, &endpoint.FakeEndpointProxy{}, &allocator.FakeIdentityAllocator{}, 10, endpoint.StateReady)
				ep.SetContainerID("")
			},
		},
		{
			name: "endpoint by docker endpoint ID",
			preTestRun: func() {
				ep.SetDockerEndpointID("1234")
				mgr.expose(ep)
			},
			setupArgs: func() args {
				return args{
					endpointid.NewID(endpointid.DockerEndpointPrefix, "1234"),
				}
			},
			setupWant: func() want {
				return want{
					ep:       nil,
					err:      ErrUnsupportedWhenMultiNIC{Prefix: endpointid.DockerEndpointPrefix.String()},
					errCheck: Equals,
				}
			},
			postTestRun: func() {
				mgr.WaitEndpointRemoved(ep)
				ep = endpoint.NewEndpointWithState(s, &endpoint.FakeEndpointProxy{}, &allocator.FakeIdentityAllocator{}, 10, endpoint.StateReady)
				ep.SetDockerEndpointID("")
			},
		},
		{
			name: "endpoint by container name",
			preTestRun: func() {
				ep.SetContainerName("foo")
				mgr.expose(ep)
			},
			setupArgs: func() args {
				return args{
					endpointid.NewID(endpointid.ContainerNamePrefix, "foo"),
				}
			},
			setupWant: func() want {
				return want{
					ep:       nil,
					err:      ErrUnsupportedWhenMultiNIC{Prefix: endpointid.ContainerNamePrefix.String()},
					errCheck: Equals,
				}
			},
			postTestRun: func() {
				mgr.WaitEndpointRemoved(ep)
				ep = endpoint.NewEndpointWithState(s, &endpoint.FakeEndpointProxy{}, &allocator.FakeIdentityAllocator{}, 10, endpoint.StateReady)
				ep.SetContainerName("")
			},
		},
		{
			name: "endpoint by pod name",
			preTestRun: func() {
				ep.SetK8sNamespace("default")
				ep.SetK8sPodName("foo")
				mgr.expose(ep)
			},
			setupArgs: func() args {
				return args{
					endpointid.NewID(endpointid.PodNamePrefix, "default/foo"),
				}
			},
			setupWant: func() want {
				return want{
					ep:       nil,
					err:      ErrUnsupportedWhenMultiNIC{Prefix: endpointid.PodNamePrefix.String()},
					errCheck: Equals,
				}
			},
			postTestRun: func() {
				mgr.WaitEndpointRemoved(ep)
				ep = endpoint.NewEndpointWithState(s, &endpoint.FakeEndpointProxy{}, &allocator.FakeIdentityAllocator{}, 10, endpoint.StateReady)
				ep.SetK8sPodName("")
			},
		},
		{
			name: "endpoint by ipv4",
			preTestRun: func() {
				ipv4, err := addressing.NewCiliumIPv4("127.0.0.1")
				ep.IPv4 = ipv4
				c.Assert(err, IsNil)
				mgr.expose(ep)
			},
			setupArgs: func() args {
				return args{
					endpointid.NewID(endpointid.IPv4Prefix, "127.0.0.1"),
				}
			},
			setupWant: func() want {
				return want{
					ep:       ep,
					err:      nil,
					errCheck: Equals,
				}
			},
			postTestRun: func() {
				mgr.WaitEndpointRemoved(ep)
				ep = endpoint.NewEndpointWithState(s, &endpoint.FakeEndpointProxy{}, &allocator.FakeIdentityAllocator{}, 10, endpoint.StateReady)
				ep.IPv4 = nil
			},
		},
	}
	for _, tt := range tests {
		tt.preTestRun()
		args := tt.setupArgs()
		want := tt.setupWant()
		got, err := mgr.Lookup(args.id)
		c.Assert(err, want.errCheck, want.err, Commentf("Test Name: %s", tt.name))
		c.Assert(got, checker.DeepEquals, want.ep, Commentf("Test Name: %s", tt.name))
		tt.postTestRun()
	}
}

func (s *EndpointManagerSuite) TestLookupEndpointsByContainerID(c *C) {
	option.Config.EnableGoogleMultiNIC = true
	defer func() {
		option.Config.EnableGoogleMultiNIC = false
	}()
	mgr := NewEndpointManager(&dummyEpSyncher{})
	ep1 := endpoint.NewEndpointWithState(s, &endpoint.FakeEndpointProxy{}, &allocator.FakeIdentityAllocator{}, 3, endpoint.StateReady)
	ep1.ID = 1
	ep2 := endpoint.NewEndpointWithState(s, &endpoint.FakeEndpointProxy{}, &allocator.FakeIdentityAllocator{}, 3, endpoint.StateReady)
	ep2.ID = 2
	type args struct {
		id string
	}
	type want struct {
		eps []*endpoint.Endpoint
	}
	tests := []struct {
		name        string
		setupArgs   func() args
		setupWant   func() want
		preTestRun  func()
		postTestRun func()
	}{
		{
			name: "non-existing container ID",
			preTestRun: func() {
			},
			setupArgs: func() args {
				return args{
					"foo",
				}
			},
			setupWant: func() want {
				return want{
					eps: nil,
				}
			},
			postTestRun: func() {
			},
		},
		{
			name: "existing container ID single endpoint",
			preTestRun: func() {
				ep1.SetContainerID("foo")
				mgr.expose(ep1)
			},
			setupArgs: func() args {
				return args{
					"foo",
				}
			},
			setupWant: func() want {
				return want{
					eps: []*endpoint.Endpoint{ep1},
				}
			},
			postTestRun: func() {
				mgr.WaitEndpointRemoved(ep1)
				ep1.SetContainerID("")
			},
		},
		{
			name: "existing container ID two endpoints",
			preTestRun: func() {
				ep1.SetContainerID("foo")
				ep2.SetContainerID("foo")
				mgr.expose(ep1)
				mgr.expose(ep2)
			},
			setupArgs: func() args {
				return args{
					"foo",
				}
			},
			setupWant: func() want {
				return want{
					eps: []*endpoint.Endpoint{ep1, ep2},
				}
			},
			postTestRun: func() {
				mgr.WaitEndpointRemoved(ep1)
				mgr.WaitEndpointRemoved(ep2)
				ep1.SetContainerID("")
				ep2.SetContainerID("")
			},
		},
	}
	for _, tt := range tests {
		tt.preTestRun()
		args := tt.setupArgs()
		want := tt.setupWant()
		got := mgr.LookupEndpointsByContainerID(args.id)
		c.Assert(got, checker.DeepEquals, want.eps, Commentf("Test Name: %s", tt.name))
		tt.postTestRun()
	}
}

func (s *EndpointManagerSuite) TestLookupEndpointsByPodName(c *C) {
	option.Config.EnableGoogleMultiNIC = true
	defer func() {
		option.Config.EnableGoogleMultiNIC = false
	}()
	mgr := NewEndpointManager(&dummyEpSyncher{})
	ep1 := endpoint.NewEndpointWithState(s, &endpoint.FakeEndpointProxy{}, &allocator.FakeIdentityAllocator{}, 3, endpoint.StateReady)
	ep1.ID = 1
	ep2 := endpoint.NewEndpointWithState(s, &endpoint.FakeEndpointProxy{}, &allocator.FakeIdentityAllocator{}, 3, endpoint.StateReady)
	ep2.ID = 2
	type args struct {
		id string
	}
	type want struct {
		eps []*endpoint.Endpoint
	}
	tests := []struct {
		name        string
		setupArgs   func() args
		setupWant   func() want
		preTestRun  func()
		postTestRun func()
	}{
		{
			name: "non-existing pod name",
			preTestRun: func() {
			},
			setupArgs: func() args {
				return args{
					"foo",
				}
			},
			setupWant: func() want {
				return want{
					eps: nil,
				}
			},
			postTestRun: func() {
			},
		},
		{
			name: "existing container ID single endpoint",
			preTestRun: func() {
				ep1.SetK8sNamespace("default")
				ep1.SetK8sPodName("foo")
				mgr.expose(ep1)
			},
			setupArgs: func() args {
				return args{
					"default/foo",
				}
			},
			setupWant: func() want {
				return want{
					eps: []*endpoint.Endpoint{ep1},
				}
			},
			postTestRun: func() {
				mgr.WaitEndpointRemoved(ep1)
				ep1.SetK8sPodName("")
				ep1.SetK8sNamespace("")
			},
		},
		{
			name: "existing container ID two endpoints",
			preTestRun: func() {
				ep1.SetK8sNamespace("default")
				ep2.SetK8sNamespace("default")
				ep1.SetK8sPodName("foo")
				ep2.SetK8sPodName("foo")
				mgr.expose(ep1)
				mgr.expose(ep2)
			},
			setupArgs: func() args {
				return args{
					"default/foo",
				}
			},
			setupWant: func() want {
				return want{
					eps: []*endpoint.Endpoint{ep1, ep2},
				}
			},
			postTestRun: func() {
				mgr.WaitEndpointRemoved(ep1)
				mgr.WaitEndpointRemoved(ep2)
				ep1.SetK8sNamespace("")
				ep2.SetK8sNamespace("")
				ep1.SetK8sPodName("")
				ep2.SetK8sPodName("")
			},
		},
	}
	for _, tt := range tests {
		tt.preTestRun()
		args := tt.setupArgs()
		want := tt.setupWant()
		got := mgr.LookupEndpointsByPodName(args.id)
		c.Assert(got, checker.DeepEquals, want.eps, Commentf("Test Name: %s", tt.name))
		tt.postTestRun()
	}
}

func (s *EndpointManagerSuite) TestLookupPrimaryEndpointByContainerID(c *C) {
	option.Config.EnableGoogleMultiNIC = true
	defer func() {
		option.Config.EnableGoogleMultiNIC = false
	}()
	mgr := NewEndpointManager(&dummyEpSyncher{})
	ep1 := endpoint.NewEndpointWithState(s, &endpoint.FakeEndpointProxy{}, &allocator.FakeIdentityAllocator{}, 3, endpoint.StateReady)
	ep1.ID = 1
	ep2 := endpoint.NewEndpointWithState(s, &endpoint.FakeEndpointProxy{}, &allocator.FakeIdentityAllocator{}, 3, endpoint.StateReady)
	ep2.ID = 2
	type args struct {
		id string
	}
	type want struct {
		ep *endpoint.Endpoint
	}
	tests := []struct {
		name        string
		setupArgs   func() args
		setupWant   func() want
		preTestRun  func()
		postTestRun func()
	}{
		{
			name: "non-existing pod name",
			preTestRun: func() {
			},
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
			postTestRun: func() {
			},
		},
		{
			name: "existing container ID single endpoint",
			preTestRun: func() {
				ep1.SetContainerID("foo")
				mgr.expose(ep1)
			},
			setupArgs: func() args {
				return args{
					"foo",
				}
			},
			setupWant: func() want {
				return want{
					ep: ep1,
				}
			},
			postTestRun: func() {
				mgr.WaitEndpointRemoved(ep1)
				ep1.SetContainerID("")
			},
		},
		{
			name: "existing container ID two endpoints",
			preTestRun: func() {
				ep1.SetContainerID("foo")
				ep2.SetContainerID("foo")
				ep1.SetDeviceTypeForTest(endpoint.EndpointDeviceMACVLAN)
				mgr.expose(ep1)
				mgr.expose(ep2)
			},
			setupArgs: func() args {
				return args{
					"foo",
				}
			},
			setupWant: func() want {
				return want{
					ep: ep2,
				}
			},
			postTestRun: func() {
				mgr.WaitEndpointRemoved(ep1)
				mgr.WaitEndpointRemoved(ep2)
				ep1.SetContainerID("")
				ep2.SetContainerID("")
				ep1.SetDeviceTypeForTest(endpoint.EndpointDeviceVETH)
			},
		},
	}
	for _, tt := range tests {
		tt.preTestRun()
		args := tt.setupArgs()
		want := tt.setupWant()
		got := mgr.LookupPrimaryEndpointByContainerID(args.id)
		c.Assert(got, checker.DeepEquals, want.ep, Commentf("Test Name: %s", tt.name))
		tt.postTestRun()
	}
}

func (s *EndpointManagerSuite) TestLookupPrimaryEndpointByPodName(c *C) {
	option.Config.EnableGoogleMultiNIC = true
	defer func() {
		option.Config.EnableGoogleMultiNIC = false
	}()
	mgr := NewEndpointManager(&dummyEpSyncher{})
	ep1 := endpoint.NewEndpointWithState(s, &endpoint.FakeEndpointProxy{}, &allocator.FakeIdentityAllocator{}, 3, endpoint.StateReady)
	ep1.ID = 1
	ep2 := endpoint.NewEndpointWithState(s, &endpoint.FakeEndpointProxy{}, &allocator.FakeIdentityAllocator{}, 3, endpoint.StateReady)
	ep2.ID = 2
	type args struct {
		id string
	}
	type want struct {
		ep *endpoint.Endpoint
	}
	tests := []struct {
		name        string
		setupArgs   func() args
		setupWant   func() want
		preTestRun  func()
		postTestRun func()
	}{
		{
			name: "non-existing pod name",
			preTestRun: func() {
			},
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
			postTestRun: func() {
			},
		},
		{
			name: "existing container ID single endpoint",
			preTestRun: func() {
				ep1.SetK8sNamespace("default")
				ep1.SetK8sPodName("foo")
				mgr.expose(ep1)
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
			postTestRun: func() {
				mgr.WaitEndpointRemoved(ep1)
				ep1.SetK8sPodName("")
				ep1.SetK8sNamespace("")
			},
		},
		{
			name: "existing container ID two endpoints",
			preTestRun: func() {
				ep1.SetK8sNamespace("default")
				ep2.SetK8sNamespace("default")
				ep1.SetK8sPodName("foo")
				ep2.SetK8sPodName("foo")
				ep1.SetDeviceTypeForTest(endpoint.EndpointDeviceMACVLAN)
				mgr.expose(ep1)
				mgr.expose(ep2)
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
			postTestRun: func() {
				mgr.WaitEndpointRemoved(ep1)
				mgr.WaitEndpointRemoved(ep2)
				ep1.SetK8sNamespace("")
				ep2.SetK8sNamespace("")
				ep1.SetK8sPodName("")
				ep2.SetK8sPodName("")
				ep1.SetDeviceTypeForTest(endpoint.EndpointDeviceVETH)
			},
		},
	}
	for _, tt := range tests {
		tt.preTestRun()
		args := tt.setupArgs()
		want := tt.setupWant()
		got := mgr.LookupPrimaryEndpointByPodName(args.id)
		c.Assert(got, checker.DeepEquals, want.ep, Commentf("Test Name: %s", tt.name))
		tt.postTestRun()
	}
}

func (s *EndpointManagerSuite) TestUpdateReferencesMultiNIC(c *C) {
	option.Config.EnableGoogleMultiNIC = true
	defer func() {
		option.Config.EnableGoogleMultiNIC = false
	}()
	mgr := NewEndpointManager(&dummyEpSyncher{})
	ep := endpoint.NewEndpointWithState(s, &endpoint.FakeEndpointProxy{}, &allocator.FakeIdentityAllocator{}, 6, endpoint.StateReady)
	type args struct {
		ep *endpoint.Endpoint
	}
	type want struct {
		ep       *endpoint.Endpoint
		err      error
		errCheck Checker
	}
	tests := []struct {
		name        string
		setupArgs   func() args
		setupWant   func() want
		preTestRun  func()
		postTestRun func()
	}{
		{
			name: "Updating all references",
			preTestRun: func() {
				ep.ID = 1
				mgr.expose(ep)
			},
			setupArgs: func() args {
				// Update endpoint before running test
				ep.SetK8sNamespace("default")
				ep.SetK8sPodName("foo")
				ep.SetContainerID("container")
				ep.SetDockerEndpointID("dockerendpointID")
				ip, err := addressing.NewCiliumIPv4("127.0.0.1")
				c.Assert(err, IsNil)
				ep.IPv4 = ip
				ep.SetContainerName("containername")
				return args{
					ep: ep,
				}
			},
			setupWant: func() want {
				return want{
					ep: ep,
				}
			},
			postTestRun: func() {
				mgr.WaitEndpointRemoved(ep)
				ep.SetK8sNamespace("")
				ep.SetK8sPodName("")
				ep.SetContainerID("")
				ep.SetDockerEndpointID("")
				ep.IPv4 = nil
				ep.SetContainerName("")
			},
		},
	}
	for _, tt := range tests {
		tt.preTestRun()
		args := tt.setupArgs()
		want := tt.setupWant()
		mgr.updateReferencesLocked(args.ep, args.ep.IdentifiersLocked())

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
		tt.postTestRun()
	}
}

func (s *EndpointManagerSuite) TestRemoveMultiNIC(c *C) {
	option.Config.EnableGoogleMultiNIC = true
	defer func() {
		option.Config.EnableGoogleMultiNIC = false
	}()
	mgr := NewEndpointManager(&dummyEpSyncher{})
	ep := endpoint.NewEndpointWithState(s, &endpoint.FakeEndpointProxy{}, &allocator.FakeIdentityAllocator{}, 7, endpoint.StateReady)
	tests := []struct {
		name        string
		preTestRun  func()
		postTestRun func()
	}{
		{
			name: "Updating all references",
			preTestRun: func() {
				ep.ID = 1
				ep.SetContainerID("foo")
				ep.SetK8sPodName("bar")
				mgr.expose(ep)
			},
			postTestRun: func() {
				ep.SetContainerID("")
				ep.SetK8sPodName("")
			},
		},
	}
	for _, tt := range tests {
		tt.preTestRun()

		mgr.RemoveAll()
		c.Assert(len(mgr.endpoints), Equals, 0, Commentf("Test Name: %s", tt.name))
		c.Assert(len(mgr.endpointsAux), Equals, 0, Commentf("Test Name: %s", tt.name))
		c.Assert(len(mgr.endpointsMultiNIC), Equals, 0, Commentf("Test Name: %s", tt.name))
		tt.postTestRun()
	}
}
