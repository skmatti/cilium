// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package metrics

import (
	"crypto/tls"
	"errors"
	"net/http"
	"time"

	"github.com/cilium/cilium/pkg/crypto/certloader"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/metrics/metric"
	"github.com/cilium/hive/cell"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/sirupsen/logrus"
)

type googleMetricsManager struct {
	logger     logrus.FieldLogger
	shutdowner hive.Shutdowner

	server           http.Server
	tlsConfig        *tls.Config
	metricsTLSConfig *certloader.WatchedServerConfig
	metrics          []metric.WithMetadata

	SharedCfg SharedConfig
}

func (mm *googleMetricsManager) Start(ctx cell.HookContext) error {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(Registry, promhttp.HandlerOpts{}))
	mm.server.Handler = mux

	go func() {
		mm.logger.WithField("address", mm.server.Addr).Info("Starting metrics server")
		if mm.SharedCfg.OperatorEnableMetricsServerTLS {
			metricsTLSConfigChan, err := certloader.FutureWatchedServerConfig(
				mm.logger.WithField(logfields.Config, "operator-metrics-server-tls"),
				mm.SharedCfg.OperatorMetricsServerTLSClientCAFiles,
				mm.SharedCfg.OperatorMetricsServerTLSCertFile,
				mm.SharedCfg.OperatorMetricsServerTLSKeyFile,
			)
			if err == nil {
				waitingMsgTimeout := time.After(30 * time.Second)
				for mm.metricsTLSConfig == nil {
					select {
					case mm.metricsTLSConfig = <-metricsTLSConfigChan:
					case <-waitingMsgTimeout:
						mm.logger.Info("Waiting for Operator metrics server TLS certificate and key files to be created")
					case <-ctx.Done():
						mm.logger.Info("timeout while waiting for Operator metrics server TLS certificate and key files to be created")
						return
					}
				}
			}
		}

		var err error

		if mm.SharedCfg.OperatorEnableMetricsServerTLS {
			if mm.metricsTLSConfig != nil {
				mm.server.TLSConfig = mm.metricsTLSConfig.ServerConfig(&tls.Config{ //nolint:gosec
					MinVersion: tls.VersionTLS13,
				})
				err = mm.server.ListenAndServeTLS("", "")
			} else {
				mm.logger.Info(" Operator Metrics Server: Not started: TLS Configuration Error")
				err = http.ErrServerClosed
			}
		} else {
			err = mm.server.ListenAndServe()
		}
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			mm.logger.Error("Unable to start metrics server", logfields.Error, err)
			mm.shutdowner.Shutdown()
		}

	}()

	return nil
}

func (mm *googleMetricsManager) Stop(ctx cell.HookContext) error {
	if mm.metricsTLSConfig != nil {
		mm.metricsTLSConfig.Stop()
	}

	if err := mm.server.Shutdown(ctx); err != nil {
		mm.logger.WithError(err).Error("Shutdown operator metrics server failed")
		return err
	}
	return nil
}
