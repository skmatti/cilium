package cilium

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/api/v1/server"
	"github.com/cilium/hive/cell"
	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
)

func TestProvideTCPHandler(t *testing.T) {
	// Use test logger to capture logs
	logger, hook := test.NewNullLogger()

	// Mock server.Server
	// We can use the struct directly and set the handler
	srv := new(server.Server)
	apiCalled := false
	apiHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		apiCalled = true
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("api response"))
	})
	srv.SetHandler(apiHandler)

	handler := provideTCPHandler(tcpHandlerParams{
		Log:    logger,
		Server: srv,
	})

	t.Run("GET /", func(t *testing.T) {
		apiCalled = false
		hook.Reset()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, "api response", w.Body.String())
		assert.True(t, apiCalled, "API handler should have been called")
		assert.Empty(t, hook.Entries)
	})

	t.Run("PUT /", func(t *testing.T) {
		hook.Reset()
		req := httptest.NewRequest(http.MethodPut, "/", nil)
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
		assert.Len(t, hook.Entries, 1)
		assert.Equal(t, logrus.ErrorLevel, hook.LastEntry().Level)
		assert.Contains(t, hook.LastEntry().Message, "Blocked PUT request")
	})

	t.Run("DELETE /", func(t *testing.T) {
		hook.Reset()
		req := httptest.NewRequest(http.MethodDelete, "/", nil)
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
		assert.Len(t, hook.Entries, 1)
		assert.Equal(t, logrus.ErrorLevel, hook.LastEntry().Level)
		assert.Contains(t, hook.LastEntry().Message, "Blocked DELETE request")
	})

	t.Run("POST /", func(t *testing.T) {
		hook.Reset()
		req := httptest.NewRequest(http.MethodPost, "/", nil)
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
		assert.Len(t, hook.Entries, 1)
		assert.Equal(t, logrus.ErrorLevel, hook.LastEntry().Level)
		assert.Contains(t, hook.LastEntry().Message, "Blocked POST request")
	})

	t.Run("Missing Server", func(t *testing.T) {
		hook.Reset()
		handler := provideTCPHandler(tcpHandlerParams{
			Log:    logger,
			Server: nil,
		})

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
		assert.Len(t, hook.Entries, 1)
		assert.Equal(t, logrus.WarnLevel, hook.LastEntry().Level)
		assert.Contains(t, hook.LastEntry().Message, "Cilium API Server dependency is missing")
	})
}

func TestConfigFlags(t *testing.T) {
	var cfg Config
	flags := pflag.NewFlagSet("test", pflag.ContinueOnError)
	cfg.Flags(flags)

	assert.NotNil(t, flags.Lookup(CiliumApiTcpPort))
	assert.True(t, flags.Lookup(CiliumApiTcpPort).Hidden)
	assert.NotNil(t, flags.Lookup(CiliumApiTcpEnabled))
	assert.True(t, flags.Lookup(CiliumApiTcpEnabled).Hidden)
	assert.NotNil(t, flags.Lookup(CiliumAPIServerCertFile))
	assert.True(t, flags.Lookup(CiliumAPIServerCertFile).Hidden)
	assert.NotNil(t, flags.Lookup(CiliumAPIServerKeyFile))
	assert.True(t, flags.Lookup(CiliumAPIServerKeyFile).Hidden)
	assert.NotNil(t, flags.Lookup(CiliumAPIServerCAFile))
	assert.True(t, flags.Lookup(CiliumAPIServerCAFile).Hidden)
}

type mockLifecycle struct {
	hooks []cell.HookInterface
}

func (m *mockLifecycle) Append(h cell.HookInterface) {
	m.hooks = append(m.hooks, h)
}

func (m *mockLifecycle) Start(log *slog.Logger, ctx context.Context) error { return nil }
func (m *mockLifecycle) Stop(log *slog.Logger, ctx context.Context) error  { return nil }
func (m *mockLifecycle) PrintHooks()                                       {}

func TestRegisterServer(t *testing.T) {
	t.Run("Disabled", func(t *testing.T) {
		cfg := Config{
			CiliumApiTcpEnabled: false,
		}
		lc := &mockLifecycle{}
		logger, hook := test.NewNullLogger()

		err := registerServer(lc, logger, nil, cfg)
		assert.NoError(t, err)

		assert.Empty(t, lc.hooks, "Should not register hooks when disabled")
		assert.Empty(t, hook.Entries)
	})

	t.Run("Disabled with Certs", func(t *testing.T) {
		cfg := Config{
			CiliumApiTcpEnabled:     false,
			CiliumAPIServerCertFile: "/tmp/cert",
			CiliumAPIServerKeyFile:  "/tmp/key",
		}
		lc := &mockLifecycle{}
		logger, hook := test.NewNullLogger()

		registerServer(lc, logger, nil, cfg)

		assert.Empty(t, lc.hooks, "Should not register hooks when disabled, even if certs are present")
		assert.Empty(t, hook.Entries)
	})

	t.Run("Enabled Missing Certs", func(t *testing.T) {
		cfg := Config{
			CiliumApiTcpEnabled: true,
			CiliumApiTcpPort:    0,
		}
		lc := &mockLifecycle{}
		logger, hook := test.NewNullLogger()

		// Should return error because certs are missing
		err := registerServer(lc, logger, nil, cfg)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "missing certificate or key file")

		assert.Empty(t, lc.hooks, "Should not register hooks when config is invalid")
		assert.Len(t, hook.Entries, 1)
		assert.Equal(t, logrus.ErrorLevel, hook.LastEntry().Level)
	})

	t.Run("Start Failure", func(t *testing.T) {
		cfg := Config{
			CiliumApiTcpEnabled: true,
			CiliumApiTcpPort:    -1, // Invalid port
		}
		lc := &mockLifecycle{}
		logger, hook := test.NewNullLogger()

		err := registerServer(lc, logger, nil, cfg)
		assert.NoError(t, err)

		assert.Empty(t, lc.hooks, "Should not register hooks when validation fails")
		assert.Len(t, hook.Entries, 1)
		assert.Equal(t, logrus.ErrorLevel, hook.LastEntry().Level)
		assert.Contains(t, hook.LastEntry().Message, "Invalid Cilium TCP API port")
	})

	t.Run("Secure Mode", func(t *testing.T) {
		certFile, keyFile, caFile := generateTestCerts(t)

		cfg := Config{
			CiliumApiTcpEnabled:     true,
			CiliumApiTcpPort:        9882,
			CiliumAPIServerCertFile: certFile,
			CiliumAPIServerKeyFile:  keyFile,
			CiliumAPIServerCAFile:   caFile,
		}
		lc := &mockLifecycle{}
		logger, hook := test.NewNullLogger()

		registerServer(lc, logger, nil, cfg)

		require.Len(t, lc.hooks, 1)
		err := lc.hooks[0].Start(cell.HookContext(context.Background()))
		assert.NoError(t, err)

		require.NotEmpty(t, hook.Entries)
		assert.Contains(t, hook.LastEntry().Message, "Starting Cilium Secure TCP API server")
	})

	t.Run("Fatal: Missing Cert File", func(t *testing.T) {
		cfg := Config{
			CiliumApiTcpEnabled:     true,
			CiliumApiTcpPort:        9882,
			CiliumAPIServerCertFile: "/non-existent/cert.pem",
			CiliumAPIServerKeyFile:  "/non-existent/key.pem",
			CiliumAPIServerCAFile:   "/non-existent/ca.pem",
		}
		lc := &mockLifecycle{}
		logger, _ := test.NewNullLogger()

		// Capture exit
		var exitCode int
		logger.ExitFunc = func(code int) {
			exitCode = code
			panic("captured exit")
		}

		defer func() {
			if r := recover(); r != nil {
				assert.Equal(t, "captured exit", r)
				assert.Equal(t, 1, exitCode)
			}
		}()

		registerServer(lc, logger, nil, cfg)
		t.Fatal("Should have panicked via logger.ExitFunc")
	})

	t.Run("Hot Reload", func(t *testing.T) {
		// Use a directory that we can write to
		dir := t.TempDir()
		certFile := filepath.Join(dir, "tls.crt")
		keyFile := filepath.Join(dir, "tls.key")
		caFile := filepath.Join(dir, "ca.crt")

		// Initial Certs
		writeTestCerts(t, certFile, keyFile, caFile)

		cfg := Config{
			CiliumApiTcpEnabled:     true,
			CiliumApiTcpPort:        9883,
			CiliumAPIServerCertFile: certFile,
			CiliumAPIServerKeyFile:  keyFile,
			CiliumAPIServerCAFile:   caFile,
		}
		lc := &mockLifecycle{}
		logger, hook := test.NewNullLogger()

		registerServer(lc, logger, nil, cfg)

		require.Len(t, lc.hooks, 1)
		err := lc.hooks[0].Start(cell.HookContext(context.Background()))
		assert.NoError(t, err)

		// Wait for start
		assert.Eventually(t, func() bool {
			return hook.LastEntry() != nil
		}, 1*time.Second, 10*time.Millisecond, "Failed to start. Logs: %v", hook.Entries)

		require.NotNil(t, hook.LastEntry())
		assert.Contains(t, hook.LastEntry().Message, "Starting Cilium Secure TCP API server")

		hook.Reset()

		// Update Certs (Hot Reload)
		// Sleep briefly to ensure filesystem mtime change if needed (ext4 has coarse mtime sometimes)
		time.Sleep(100 * time.Millisecond)
		writeTestCerts(t, certFile, keyFile, caFile)

		// Wait for reload log
		assert.Eventually(t, func() bool {
			// Check all entries since reset
			for _, e := range hook.AllEntries() {
				if e.Message == "Keypair updated" {
					return true
				}
			}
			return false
		}, 2*time.Second, 100*time.Millisecond, "Failed to detect keypair update")

		// Cleanup
		lc.hooks[0].Stop(cell.HookContext(context.Background()))
	})

	t.Run("Start Retry Failure", func(t *testing.T) {
		certFile, keyFile, caFile := generateTestCerts(t)

		// Listen on a port to force a conflict
		l, err := net.Listen("tcp", ":0")
		require.NoError(t, err)
		defer l.Close()
		port := l.Addr().(*net.TCPAddr).Port

		cfg := Config{
			CiliumApiTcpEnabled:     true,
			CiliumApiTcpPort:        int32(port),
			CiliumAPIServerCertFile: certFile,
			CiliumAPIServerKeyFile:  keyFile,
			CiliumAPIServerCAFile:   caFile,
		}
		lc := &mockLifecycle{}
		logger, hook := test.NewNullLogger()

		registerServer(lc, logger, nil, cfg)
		require.Len(t, lc.hooks, 1)

		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()

		err = lc.hooks[0].Start(cell.HookContext(ctx))
		assert.NoError(t, err) // Hook itself doesn't return error on exhaust, logs it instead

		assert.Eventually(t, func() bool {
			for _, e := range hook.AllEntries() {
				if e.Message == "Cilium TCP API server failed to listen after retries" {
					return true
				}
			}
			return false
		}, 2*time.Second, 50*time.Millisecond)
	})

	t.Run("Start Retry Success", func(t *testing.T) {
		certFile, keyFile, caFile := generateTestCerts(t)

		// Listen on a port to force a conflict initially
		l, err := net.Listen("tcp", ":0")
		require.NoError(t, err)
		port := l.Addr().(*net.TCPAddr).Port

		// Close it after a small delay to allow a retry to succeed
		go func() {
			time.Sleep(200 * time.Millisecond)
			l.Close()
		}()

		cfg := Config{
			CiliumApiTcpEnabled:     true,
			CiliumApiTcpPort:        int32(port),
			CiliumAPIServerCertFile: certFile,
			CiliumAPIServerKeyFile:  keyFile,
			CiliumAPIServerCAFile:   caFile,
		}
		lc := &mockLifecycle{}
		logger, hook := test.NewNullLogger()

		registerServer(lc, logger, nil, cfg)
		require.Len(t, lc.hooks, 1)

		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()

		err = lc.hooks[0].Start(cell.HookContext(ctx))
		assert.NoError(t, err)

		lc.hooks[0].Stop(cell.HookContext(context.Background()))

		assert.Eventually(t, func() bool {
			for _, e := range hook.AllEntries() {
				if e.Level == logrus.WarnLevel && e.Message == "Failed to listen on :"+fmt.Sprint(port)+" (attempt 1/4), retrying..." {
					return true
				}
			}
			return false
		}, 2*time.Second, 50*time.Millisecond)
	})
}

func generateTestCerts(t *testing.T) (string, string, string) {
	dir := t.TempDir()
	certFile := filepath.Join(dir, "tls.crt")
	keyFile := filepath.Join(dir, "tls.key")
	caFile := filepath.Join(dir, "ca.crt")
	writeTestCerts(t, certFile, keyFile, caFile)
	return certFile, keyFile, caFile
}

func writeTestCerts(t *testing.T, certFile, keyFile, caFile string) {
	t.Helper()

	// Generate CA
	caPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	caTemplate := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test CA"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	caDer, err := x509.CreateCertificate(rand.Reader, &caTemplate, &caTemplate, &caPriv.PublicKey, caPriv)
	require.NoError(t, err)

	// Generate Server Cert
	srvPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	srvTemplate := x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			CommonName: "cilium-agent.kube-system.svc",
		},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(time.Hour),
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	srvDer, err := x509.CreateCertificate(rand.Reader, &srvTemplate, &caTemplate, &srvPriv.PublicKey, caPriv)
	require.NoError(t, err)

	// Write to files
	err = os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDer}), 0644)
	require.NoError(t, err)

	err = os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srvDer}), 0644)
	require.NoError(t, err)

	privBytes, err := x509.MarshalECPrivateKey(srvPriv)
	require.NoError(t, err)
	err = os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privBytes}), 0600)
	require.NoError(t, err)
}
