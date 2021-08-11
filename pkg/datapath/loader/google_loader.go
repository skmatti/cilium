package loader

import (
	"context"

	"github.com/cilium/cilium/pkg/datapath"
	"github.com/cilium/cilium/pkg/datapath/connector"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/sirupsen/logrus"
)

func setupMultiNICDataPath(ctx context.Context, ep datapath.Endpoint, objPath string) error {
	// Graft from-container section for the egress direction.
	if err := graftDatapath(ctx, ep.MapPath(), objPath, "from-container", int(connector.EgressMapIndex)); err != nil {
		scopedLog := ep.Logger(Subsystem).WithFields(logrus.Fields{
			logfields.Path: objPath,
		})
		// Don't log an error here if the context was canceled or timed out;
		// this log message should only represent failures with respect to
		// loading the program.
		if ctx.Err() == nil {
			scopedLog.WithError(err).Warn("JoinEP: Failed to load program")
		}
		return err
	}
	// Graft to-container section for the ingress direction.
	if err := graftDatapath(ctx, ep.MapPath(), objPath, "to-container", int(connector.IngressMapIndex)); err != nil {
		scopedLog := ep.Logger(Subsystem).WithFields(logrus.Fields{
			logfields.Path: objPath,
		})
		// Don't log an error here if the context was canceled or timed out;
		// this log message should only represent failures with respect to
		// loading the program.
		if ctx.Err() == nil {
			scopedLog.WithError(err).Warn("JoinEP: Failed to load program")
		}
		return err
	}
	return nil
}
