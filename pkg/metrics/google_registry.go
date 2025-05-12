// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package metrics

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"

	"github.com/cilium/hive"
	"github.com/cilium/hive/cell"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/cilium/cilium/pkg/crypto/certloader"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/time"
)

func GoogleRegistry(params RegistryParams) *Registry {

	reg := &Registry{
		params: params,
	}

	reg.Reinitialize()

	// Resolve the global registry variable for as long as we still have global functions
	registryResolver.Resolve(reg)

	if params.Config.PrometheusServeAddr != "" {
		// The Handler function provides a default handler to expose metrics
		// via an HTTP server. "/metrics" is the usual endpoint for that.
		mux := http.NewServeMux()
		mux.Handle("/metrics", promhttp.HandlerFor(reg.inner, promhttp.HandlerOpts{}))
		srv := http.Server{
			Addr:    params.Config.PrometheusServeAddr,
			Handler: mux,
		}

		var metricsTLSConfig *certloader.WatchedServerConfig

		params.Lifecycle.Append(cell.Hook{
			OnStart: func(hc cell.HookContext) error {
				go func() {
					if params.DaemonConfig.AgentEnableMetricsServerTLS {
						params.Logger.Infof("Configuring mTLS for agent metrics server...")
						metricsTLSConfigChan, err := certloader.FutureWatchedServerConfig(
							params.Logger.WithField(logfields.Config, "agent-metrics-server-tls"),
							params.DaemonConfig.AgentMetricsServerTLSClientCAFiles,
							params.DaemonConfig.AgentMetricsServerTLSCertFile,
							params.DaemonConfig.AgentMetricsServerTLSKeyFile,
						)
						if err == nil {
							waitingMsgTimeout := time.After(30 * time.Second)
							for metricsTLSConfig == nil {
								select {
								case metricsTLSConfig = <-metricsTLSConfigChan:
								case <-waitingMsgTimeout:
									params.Logger.Infof("Waiting for Agent metrics server TLS certificate and key files to be created")
								case <-hc.Done():
									err = fmt.Errorf("timeout while waiting for Agent metrics server TLS certificate and key files to be created: %w", hc.Err())
									return
								}
							}
							go func() {
								<-hc.Done()
							}()
						}

					}

					params.Logger.Infof("Serving prometheus metrics on %s", params.Config.PrometheusServeAddr)
					var err error
					if params.DaemonConfig.AgentEnableMetricsServerTLS {
						if metricsTLSConfig != nil {
							srv.TLSConfig = metricsTLSConfig.ServerConfig(&tls.Config{ //nolint:gosec
								MinVersion: tls.VersionTLS13,
							})
							err = srv.ListenAndServeTLS("", "")
						} else {
							params.Logger.Info("Anetd Metrics Server: Not started: TLS Configuration Error")
							err = http.ErrServerClosed
						}

					} else {
						err = srv.ListenAndServe()
					}

					if err != nil && !errors.Is(err, http.ErrServerClosed) {
						params.Shutdowner.Shutdown(hive.ShutdownWithError(err))
					}
				}()
				return nil
			},
			OnStop: func(hc cell.HookContext) error {
				if metricsTLSConfig != nil {
					metricsTLSConfig.Stop()
				}
				return srv.Shutdown(hc)
			},
		})
	}

	return reg
}
