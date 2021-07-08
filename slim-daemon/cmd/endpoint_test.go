//go:build !privileged_tests
// +build !privileged_tests

package cmd

import (
	"testing"

	"github.com/cilium/cilium/pkg/endpoint"
)

func TestEndpointSyncControllerName(t *testing.T) {
	id := uint16(123)

	if endpoint.EndpointSyncControllerName(id) != EndpointSyncControllerName(id) {
		t.Errorf("expect internal EndpointSyncControllerName() returns the same result as endpoint.EndpointSyncControllerName(); but %q != %q",
			EndpointSyncControllerName(id),
			endpoint.EndpointSyncControllerName(id),
		)
	}
}
