//go:build !privileged_tests && integration_tests

package main

import (
	"context"
	"fmt"
	"path"
	"strings"
	"testing"

	identityCache "github.com/cilium/cilium/pkg/identity/cache"
	"github.com/cilium/cilium/pkg/ipcache"
	ciliumio "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	apilabels "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/labels"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/k8s/types"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/labels"
	. "gopkg.in/check.v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"
)

var namespaceLabel string

func init() {
	kvstore.SetupDummy("etcd")

	namespaceLabel = strings.TrimSuffix(labels.GenerateK8sLabelString(ciliumio.PodNamespaceLabel, ""), "=")

	namespaceCache = &cache.FakeCustomStore{
		GetFunc: func(obj interface{}) (item interface{}, exists bool, err error) {
			ns, ok := obj.(*slim_corev1.Namespace)
			if !ok {
				return nil, false, fmt.Errorf("input object not a namespace: %#v", obj)
			}
			if ns.Name == "valid" {
				return nil, true, nil
			}
			return nil, false, nil
		},
	}
}

func Test(t *testing.T) {
	TestingT(t)
}

type ClusterMeshServerTestSuite struct{}

var _ = Suite(&ClusterMeshServerTestSuite{})

func (s *ClusterMeshServerTestSuite) TestUpdateEndpoint(c *C) {

	testCases := []struct {
		name       string
		endpoint   *types.CiliumEndpoint
		key        string
		wantExists bool
	}{
		{
			name: "endpoint in valid namespace",
			endpoint: &types.CiliumEndpoint{
				ObjectMeta: slim_metav1.ObjectMeta{
					Name:      "ep",
					Namespace: "valid",
				},
				Networking: &v2.EndpointNetworking{
					Addressing: v2.AddressPairList{
						{
							IPV4: "10.0.0.1",
						},
					},
				},
			},
			key:        path.Join(ipcache.IPIdentitiesPath, ipcache.DefaultAddressSpace, "10.0.0.1"),
			wantExists: true,
		},
		{
			name: "endpoint in valid namespace with multiple addresses",
			endpoint: &types.CiliumEndpoint{
				ObjectMeta: slim_metav1.ObjectMeta{
					Name:      "ep",
					Namespace: "valid",
				},
				Networking: &v2.EndpointNetworking{
					Addressing: v2.AddressPairList{
						{
							IPV4: "10.0.0.1",
						},
						{
							IPV4: "10.0.0.2",
						},
					},
				},
			},
			key:        path.Join(ipcache.IPIdentitiesPath, ipcache.DefaultAddressSpace, "10.0.0.2"),
			wantExists: true,
		},
		{
			name: "endpoint not in valid namespace",
			endpoint: &types.CiliumEndpoint{
				ObjectMeta: slim_metav1.ObjectMeta{
					Name:      "ep",
					Namespace: "invalid",
				},
				Networking: &v2.EndpointNetworking{
					Addressing: v2.AddressPairList{
						{
							IPV4: "10.0.0.3",
						},
					},
				},
			},
			key:        path.Join(ipcache.IPIdentitiesPath, ipcache.DefaultAddressSpace, "10.0.0.3"),
			wantExists: false,
		},
		{
			name: "endpoint has no namespace",
			endpoint: &types.CiliumEndpoint{
				ObjectMeta: slim_metav1.ObjectMeta{
					Name:      "ep",
					Namespace: "",
				},
				Networking: &v2.EndpointNetworking{
					Addressing: v2.AddressPairList{
						{
							IPV4: "10.0.0.4",
						},
					},
				},
			},
			key:        path.Join(ipcache.IPIdentitiesPath, ipcache.DefaultAddressSpace, "10.0.0.4"),
			wantExists: false,
		},
	}

	for _, tc := range testCases {
		func() {
			defer cleanup(ipcache.IPIdentitiesPath, c)

			updateEndpoint(nil, tc.endpoint)

			checkPath(tc.key, tc.wantExists, c)
		}()
	}
}

func (s *ClusterMeshServerTestSuite) TestDeleteEndpoint(c *C) {

	testCases := []struct {
		name             string
		originalEndpoint *types.CiliumEndpoint
		endpoint         *types.CiliumEndpoint
		key              string
		wantExists       bool
	}{
		{
			name: "endpoint in valid namespace",
			originalEndpoint: &types.CiliumEndpoint{
				ObjectMeta: slim_metav1.ObjectMeta{
					Name:      "ep",
					Namespace: "valid",
				},
				Networking: &v2.EndpointNetworking{
					Addressing: v2.AddressPairList{
						{
							IPV4: "10.0.0.1",
						},
					},
				},
			},
			endpoint: &types.CiliumEndpoint{
				ObjectMeta: slim_metav1.ObjectMeta{
					Name:      "ep",
					Namespace: "valid",
				},
				Networking: &v2.EndpointNetworking{
					Addressing: v2.AddressPairList{
						{
							IPV4: "10.0.0.1",
						},
					},
				},
			},
			key:        path.Join(ipcache.IPIdentitiesPath, ipcache.DefaultAddressSpace, "10.0.0.1"),
			wantExists: false,
		},
		{
			name: "endpoint not in valid namespace",
			originalEndpoint: &types.CiliumEndpoint{
				ObjectMeta: slim_metav1.ObjectMeta{
					Name:      "ep",
					Namespace: "valid",
				},
				Networking: &v2.EndpointNetworking{
					Addressing: v2.AddressPairList{
						{
							IPV4: "10.0.0.3",
						},
					},
				},
			},
			endpoint: &types.CiliumEndpoint{
				ObjectMeta: slim_metav1.ObjectMeta{
					Name:      "ep",
					Namespace: "invalid",
				},
				Networking: &v2.EndpointNetworking{
					Addressing: v2.AddressPairList{
						{
							IPV4: "10.0.0.3",
						},
					},
				},
			},
			key:        path.Join(ipcache.IPIdentitiesPath, ipcache.DefaultAddressSpace, "10.0.0.3"),
			wantExists: true,
		},
	}

	for _, tc := range testCases {
		func() {
			defer cleanup(ipcache.IPIdentitiesPath, c)

			// Create original endpoint and check it exists
			updateEndpoint(nil, tc.originalEndpoint)
			checkPath(tc.key, true, c)

			deleteEndpoint(tc.endpoint)

			checkPath(tc.key, tc.wantExists, c)
		}()
	}
}

func (s *ClusterMeshServerTestSuite) TestUpdateIdentity(c *C) {

	testCases := []struct {
		name       string
		identity   *v2.CiliumIdentity
		key        string
		wantExists bool
	}{
		{
			name: "identity in valid namespace",
			identity: &v2.CiliumIdentity{
				ObjectMeta: metav1.ObjectMeta{
					Name: "id1",
				},
				SecurityLabels: map[string]string{
					namespaceLabel: "valid",
				},
			},
			key:        path.Join(identityCache.IdentitiesPath, "id", "id1"),
			wantExists: true,
		},
		{
			name: "identity not in valid namespace",
			identity: &v2.CiliumIdentity{
				ObjectMeta: metav1.ObjectMeta{
					Name: "id2",
				},
				SecurityLabels: map[string]string{
					namespaceLabel: "invalid",
				},
			},
			key:        path.Join(identityCache.IdentitiesPath, "id", "id2"),
			wantExists: false,
		},
		{
			name: "identity with no namespace label",
			identity: &v2.CiliumIdentity{
				ObjectMeta: metav1.ObjectMeta{
					Name: "id3",
				},
				SecurityLabels: map[string]string{
					"fooLabel": "bar",
				},
			},
			key:        path.Join(identityCache.IdentitiesPath, "id", "id3"),
			wantExists: false,
		},
	}

	for _, tc := range testCases {
		func() {
			defer cleanup(identityCache.IdentitiesPath, c)

			updateIdentity(tc.identity)

			checkPath(tc.key, tc.wantExists, c)
		}()
	}
}

func (s *ClusterMeshServerTestSuite) TestDeleteIdentity(c *C) {

	testCases := []struct {
		name             string
		originalIdentity *v2.CiliumIdentity
		identity         *v2.CiliumIdentity
		key              string
		wantExists       bool
	}{
		{
			name: "identity in valid namespace",
			originalIdentity: &v2.CiliumIdentity{
				ObjectMeta: metav1.ObjectMeta{
					Name: "id1",
				},
				SecurityLabels: map[string]string{
					namespaceLabel: "valid",
				},
			},
			identity: &v2.CiliumIdentity{
				ObjectMeta: metav1.ObjectMeta{
					Name: "id1",
				},
				SecurityLabels: map[string]string{
					namespaceLabel: "valid",
				},
			},
			key:        path.Join(identityCache.IdentitiesPath, "id", "id1"),
			wantExists: false,
		},
		{
			name: "identity not in valid namespace",
			originalIdentity: &v2.CiliumIdentity{
				ObjectMeta: metav1.ObjectMeta{
					Name: "id2",
				},
				SecurityLabels: map[string]string{
					namespaceLabel: "valid",
				},
			},
			identity: &v2.CiliumIdentity{
				ObjectMeta: metav1.ObjectMeta{
					Name: "id2",
				},
				SecurityLabels: map[string]string{
					namespaceLabel: "invalid",
				},
			},
			key:        path.Join(identityCache.IdentitiesPath, "id", "id2"),
			wantExists: true,
		},
	}

	for _, tc := range testCases {
		func() {
			defer cleanup(identityCache.IdentitiesPath, c)

			// Create original identity and check it exists
			updateIdentity(tc.originalIdentity)
			checkPath(tc.key, true, c)

			deleteIdentity(tc.identity)

			checkPath(tc.key, tc.wantExists, c)
		}()
	}
}

func (s *ClusterMeshServerTestSuite) TestBuildLabelSelector(c *C) {

	testCases := []struct {
		name          string
		labels        []string
		labelsToMatch map[string]string
		wantMatch     bool
	}{
		{
			name: "one label match",
			labels: []string{
				"tenancy.gdch.gke.io/project-name",
			},
			labelsToMatch: map[string]string{
				"tenancy.gdch.gke.io/project-name": "foo",
			},
			wantMatch: true,
		},
		{
			name: "two labels, both match",
			labels: []string{
				"tenancy.gdch.gke.io/project-name",
				"tenancy.gdch.gke.io/project-namespace",
			},
			labelsToMatch: map[string]string{
				"tenancy.gdch.gke.io/project-name":      "foo",
				"tenancy.gdch.gke.io/project-namespace": "bar",
			},
			wantMatch: true,
		},
		{
			name: "two labels, both match",
			labels: []string{
				"tenancy.gdch.gke.io/project-name",
				"tenancy.gdch.gke.io/project-namespace",
			},
			labelsToMatch: map[string]string{
				"tenancy.gdch.gke.io/project-name":      "foo",
				"tenancy.gdch.gke.io/project-namespace": "bar",
				"extra-label":                           "should-also-match",
			},
			wantMatch: true,
		},
		{
			name: "two labels, only one matches",
			labels: []string{
				"tenancy.gdch.gke.io/project-name",
				"tenancy.gdch.gke.io/project-namespace",
			},
			labelsToMatch: map[string]string{
				"tenancy.gdch.gke.io/project-name": "foo",
			},
			wantMatch: false,
		},
		{
			name: "two labels, no matches",
			labels: []string{
				"tenancy.gdch.gke.io/project-name",
				"tenancy.gdch.gke.io/project-namespace",
			},
			labelsToMatch: map[string]string{},
			wantMatch:     false,
		},
		{
			name: "two labels, no matches",
			labels: []string{
				"tenancy.gdch.gke.io/project-name",
				"tenancy.gdch.gke.io/project-namespace",
			},
			labelsToMatch: map[string]string{
				"different-label": "should-not-match",
			},
			wantMatch: false,
		},
	}

	for _, tc := range testCases {
		selector, err := buildLabelSelector(tc.labels)
		if err != nil {
			c.Errorf("unable to build label selector with labels=%v: %v", tc.labels, err)
		}

		if got := selector.Matches(apilabels.Set(tc.labelsToMatch)); got != tc.wantMatch {
			c.Errorf("labels didn't match expected: got=%t, want=%t", got, tc.wantMatch)
		}
	}
}

func cleanup(path string, c *C) {
	err := kvstore.Client().DeletePrefix(context.Background(), path)
	if err != nil {
		c.Errorf("Unable to clean up prefix %q: %v", path, err)
	}
}

func checkPath(path string, wantExists bool, c *C) {
	b, err := kvstore.Client().Get(context.Background(), path)
	if err != nil {
		c.Errorf("Failed to get from kvstore with path %s: %v", path, err)
	}

	if b == nil && wantExists {
		c.Errorf("Expected object to exist, but got no content")
	}

	if b != nil && !wantExists {
		c.Errorf("Expected object not to exist, but got content")
	}
}
