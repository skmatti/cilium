package cmd

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCreateEndpointQueue(t *testing.T) {
	ds := setupDaemonSuite(t)
	epTemplate := getEPTemplate(t, ds.d)
	epTemplate.K8sPodName = "foo-pod"
	epTemplate.K8sNamespace = "foo-ns"
	// Create the primary endpoint
	err := ds.d.CreateEndpoint(context.TODO(), epTemplate)
	require.Empty(t, err)
}
