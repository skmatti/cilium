package cilium

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/cilium/cilium/api/v1/server"
	"github.com/cilium/cilium/pkg/crypto/certloader"
	"github.com/cilium/hive/cell"
	"github.com/sirupsen/logrus"
	"github.com/spf13/pflag"
)

const (
	// CiliumApiTcpPort specifies the port for Cilium API hosted on TCP port
	CiliumApiTcpPort = "cilium-api-tcp-port"

	//CiliumApiTcpEnabled enables Cilium API on a TCP socket
	CiliumApiTcpEnabled = "cilium-api-tcp-enabled"

	// CiliumAPIServerCertFile is the path to the TLS certificate file.
	CiliumAPIServerCertFile = "cilium-api-server-cert-file"

	// CiliumAPIServerKeyFile is the path to the private key file.
	CiliumAPIServerKeyFile = "cilium-api-server-key-file"

	// CiliumAPIServerCAFile is the path to the CA certificate file.
	CiliumAPIServerCAFile = "cilium-api-server-ca-file"
)

// Cell is the hive cell that exposes the Cilium API over TCP.
var Cell = cell.Module(
	"cilium-api-tcp",
	"Exposes the Cilium API over a TCP socket",

	cell.Config(defaultConfig),
	cell.Provide(provideTCPHandler),
	cell.Invoke(registerServer),
)

type Config struct {
	// CiliumApiTcpPort is the TCP socket for the Cilium API.
	CiliumApiTcpPort int32 `mapstructure:"cilium-api-tcp-port"`
	// CiliumApiTcpEnabled is whether the Cilium API is enabled.
	CiliumApiTcpEnabled bool `mapstructure:"cilium-api-tcp-enabled"`
	// CiliumAPIServerCertFile is the path to the TLS certificate file.
	CiliumAPIServerCertFile string `mapstructure:"cilium-api-server-cert-file"`
	// CiliumAPIServerKeyFile is the path to the private key file.
	CiliumAPIServerKeyFile string `mapstructure:"cilium-api-server-key-file"`
	// CiliumAPIServerCAFile is the path to the CA certificate file.
	CiliumAPIServerCAFile string `mapstructure:"cilium-api-server-ca-file"`
}

var defaultConfig = Config{
	CiliumApiTcpPort:        9882,
	CiliumApiTcpEnabled:     false,
	CiliumAPIServerCertFile: "/var/lib/cilium/tls/cilium-api-server/tls.crt",
	CiliumAPIServerKeyFile:  "/var/lib/cilium/tls/cilium-api-server/tls.key",
	CiliumAPIServerCAFile:   "/var/lib/cilium/tls/cilium-api-server/ca.crt",
}

func (c Config) Flags(flags *pflag.FlagSet) {
	flags.Int32(CiliumApiTcpPort, c.CiliumApiTcpPort, "TCP socket for the Cilium API")
	flags.Bool(CiliumApiTcpEnabled, c.CiliumApiTcpEnabled, "Enable Cilium API on a TCP socket")
	flags.String(CiliumAPIServerCertFile, c.CiliumAPIServerCertFile, "Path to the TLS certificate file")
	flags.String(CiliumAPIServerKeyFile, c.CiliumAPIServerKeyFile, "Path to the private key file")
	flags.String(CiliumAPIServerCAFile, c.CiliumAPIServerCAFile, "Path to the CA certificate file for verifying clients")
	_ = flags.MarkHidden(CiliumApiTcpPort)
	_ = flags.MarkHidden(CiliumApiTcpEnabled)
	_ = flags.MarkHidden(CiliumAPIServerCertFile)
	_ = flags.MarkHidden(CiliumAPIServerKeyFile)
	_ = flags.MarkHidden(CiliumAPIServerCAFile)
}

type tcpHandlerParams struct {
	cell.In

	Log    logrus.FieldLogger
	Server *server.Server `optional:"true"`
}

type ciliumGetAPIHTTPHandler http.Handler

func provideTCPHandler(params tcpHandlerParams) ciliumGetAPIHTTPHandler {
	if params.Server == nil {
		params.Log.Warn("Cilium API Server dependency is missing. TCP API will return 404 for all requests.")
		return ciliumGetAPIHTTPHandler(http.NotFoundHandler())
	}

	mux := http.NewServeMux()
	mux.Handle("/", params.Server.GetHandler())

	restrictedHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			mux.ServeHTTP(w, r)
			return
		default:
			params.Log.Errorf("Blocked %s request to %s from network address %s", r.Method, r.URL.Path, r.RemoteAddr)
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}
	})

	return ciliumGetAPIHTTPHandler(restrictedHandler)
}

func registerServer(lc cell.Lifecycle, log logrus.FieldLogger, handler ciliumGetAPIHTTPHandler, cfg Config) error {
	if !cfg.CiliumApiTcpEnabled {
		return nil
	}

	if cfg.CiliumApiTcpPort < 0 || cfg.CiliumApiTcpPort > 65535 {
		log.Errorf("Invalid Cilium TCP API port: %d. Must be between 0 and 65535.", cfg.CiliumApiTcpPort)
		return nil
	}

	if cfg.CiliumAPIServerCertFile == "" || cfg.CiliumAPIServerKeyFile == "" {
		err := fmt.Errorf("Cilium API TCP server enabled but missing certificate or key file")
		log.Error(err.Error())
		return err
	}
	log.Debug("Cilium API TCP server certificate and key file provided")

	if cfg.CiliumAPIServerCAFile == "" {
		err := fmt.Errorf("Cilium API TCP server enabled but missing CA certificate file")
		log.Error(err.Error())
		return err
	}
	watcher, err := certloader.NewWatchedServerConfig(log, []string{cfg.CiliumAPIServerCAFile}, cfg.CiliumAPIServerCertFile, cfg.CiliumAPIServerKeyFile)
	if err != nil {
		log.WithError(err).Fatal("Failed to load Cilium API server certificates")
	}
	log.Debug("Cilium API TCP server certificate and key file loaded successfully")

	tlsConfig := watcher.ServerConfig(&tls.Config{
		MinVersion: tls.VersionTLS12,
		ClientAuth: tls.RequireAndVerifyClientCert,
	})
	log.Debug("Cilium API TCP server TLS config loaded successfully")
	srv := &http.Server{
		Addr:      fmt.Sprintf(":%d", cfg.CiliumApiTcpPort),
		Handler:   handler,
		TLSConfig: tlsConfig,
	}
	log.Debug("Cilium API TCP server created successfully")
	lc.Append(cell.Hook{
		OnStart: func(ctx cell.HookContext) error {
			var ln net.Listener
			var err error
			maxRetries := 3
			baseDelay := 100 * time.Millisecond

			for i := 0; i <= maxRetries; i++ {
				// We can't use srv.ListenAndServe because we want to retry just the Listen part
				// ensuring the port is available before we proceed.
				ln, err = net.Listen("tcp", srv.Addr)
				if err == nil {
					log.Debugf("Successfully bound to %s on attempt %d", srv.Addr, i+1)
					break // Successfully bound
				}

				if i < maxRetries {
					log.WithError(err).Warnf("Failed to listen on %s (attempt %d/%d), retrying...", srv.Addr, i+1, maxRetries+1)
					select {
					case <-ctx.Done():
						return ctx.Err()
					case <-time.After(baseDelay * time.Duration(1<<i)):
						// continue retry
					}
				}
			}

			if err != nil {
				log.WithError(err).Error("Cilium TCP API server failed to listen after retries")
				// Returning nil here means we log the error but don't crash the hive startup.
				return nil
			}

			// Wrap the listener with TLS since it's always secure
			ln = tls.NewListener(ln, srv.TLSConfig)
			log.Infof("Starting Cilium Secure TCP API server on %s", ln.Addr().String())

			go func() {
				// Use Serve with the listener we just created (potentially wrapped in TLS)
				if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
					log.WithError(err).Error("Cilium TCP API server failed")
				}
				log.Debug("Cilium TCP API server stopped serving")
			}()
			return nil
		},
		OnStop: func(ctx cell.HookContext) error {
			if watcher != nil {
				watcher.Stop()
				log.Debug("Cilium API TCP server watcher stopped")
			}
			log.Info("Stopping Cilium TCP API server")
			// Give it a small timeout for graceful shutdown
			shutdownCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()

			err := srv.Shutdown(shutdownCtx)
			if err != nil {
				log.WithError(err).Error("Error during Cilium TCP API server shutdown")
			} else {
				log.Debug("Cilium TCP API server shutdown completed successfully")
			}
			return err
		},
	})
	return nil
}
