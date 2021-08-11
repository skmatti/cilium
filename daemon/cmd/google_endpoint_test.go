//go:build !privileged_tests && integration_tests
// +build !privileged_tests,integration_tests

package cmd

import (
	"context"

	apiEndpoint "github.com/cilium/cilium/api/v1/server/restapi/endpoint"
	"github.com/cilium/cilium/pkg/option"

	. "gopkg.in/check.v1"
)

func (ds *DaemonSuite) TestCreateMultiNICEndpointsNoK8sEnabled(c *C) {
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
