package cmd

import (
	"context"
	"fmt"

	"github.com/cilium/cilium/api/v1/models"
)

// CreateEndpoint implements epqueue.EndpointCreationSink.
func (d *Daemon) CreateEndpoint(ctx context.Context, endpoint *models.EndpointChangeRequest) error {
	ep, _, err := d.createEndpoint(ctx, d, endpoint)
	if err != nil {
		return fmt.Errorf("create queued endpoint for %s/%s: %w", endpoint.K8sNamespace, endpoint.K8sPodName, err)
	}
	ep.Logger(daemonSubsys).Info("Successful endpoint creation")
	return nil
}
