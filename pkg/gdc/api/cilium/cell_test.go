package cilium

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"

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
	assert.NotNil(t, flags.Lookup(CiliumApiTcpEnabled))
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

	t.Run("Enabled", func(t *testing.T) {
		cfg := Config{
			CiliumApiTcpEnabled: true,
			CiliumApiTcpPort:    0,
		}
		lc := &mockLifecycle{}
		logger, hook := test.NewNullLogger()

		// Handler can be nil as registerServer creates http.Server struct but doesn't use handler until Serve
		err := registerServer(lc, logger, nil, cfg)
		assert.NoError(t, err)

		assert.Len(t, lc.hooks, 1, "Should register 1 hook when enabled")

		if len(lc.hooks) > 0 {
			h := lc.hooks[0]

			// Execute OnStart
			err := h.Start(cell.HookContext(context.Background()))
			assert.NoError(t, err)

			// Verify start logs
			assert.True(t, len(hook.Entries) > 0)
			assert.Contains(t, hook.LastEntry().Message, "Starting Cilium TCP API server")

			hook.Reset()

			// Execute OnStop
			err = h.Stop(cell.HookContext(context.Background()))
			assert.NoError(t, err)

			// Verify stop logs
			assert.True(t, len(hook.Entries) > 0)
			assert.Contains(t, hook.LastEntry().Message, "Stopping Cilium TCP API server")
		}
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
}

func TestRegisterServer_RetrySuccess(t *testing.T) {
	// Find a free port
	ln, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatalf("Failed to listen on a random port: %v", err)
	}
	port := int32(ln.Addr().(*net.TCPAddr).Port)

	// Keep the port busy for now. We will close it later.
	// Note: We use localhost to ensure we bind to the same interface if possible,
	// but registerServer binds to ":port" (all interfaces).
	// If we bind to localhost, and registerServer tries to bind to 0.0.0.0, it might still fail (conflict) or succeed depending on OS.
	// To be safe, let's use ":0" for our listener too.
	ln.Close()
	ln, err = net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		t.Fatalf("Failed to listen on port %d: %v", port, err)
	}
	defer ln.Close()

	cfg := Config{
		CiliumApiTcpEnabled: true,
		CiliumApiTcpPort:    port,
	}
	lc := &mockLifecycle{}
	logger, hook := test.NewNullLogger()

	err = registerServer(lc, logger, nil, cfg)
	assert.NoError(t, err)

	assert.Len(t, lc.hooks, 1)
	if len(lc.hooks) == 0 {
		return
	}
	h := lc.hooks[0]

	// Start in a goroutine because it will block on retry
	done := make(chan error)
	go func() {
		done <- h.Start(cell.HookContext(context.Background()))
	}()

	// Wait a bit to ensure it hits the retry logic (first attempt fails immediately)
	// Base delay is 100ms. We wait 150ms.
	time.Sleep(150 * time.Millisecond)

	// Now close the listener to allow success
	ln.Close()

	// Wait for Start to return
	select {
	case err := <-done:
		assert.NoError(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("Start timed out")
	}

	// Verify success log
	// Check if we have warnings about retries
	foundRetry := false
	for _, entry := range hook.Entries {
		if entry.Level == logrus.WarnLevel && strings.Contains(entry.Message, "Failed to listen") {
			foundRetry = true
			break
		}
	}
	assert.True(t, foundRetry, "Should have logged a retry warning")
	assert.Contains(t, hook.LastEntry().Message, "Starting Cilium TCP API server")

	// Cleanup
	err = h.Stop(cell.HookContext(context.Background()))
	assert.NoError(t, err)
}

func TestRegisterServer_RetryFail(t *testing.T) {
	// Find a free port and keep it busy
	ln, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatalf("Failed to listen on a random port: %v", err)
	}
	defer ln.Close()
	port := int32(ln.Addr().(*net.TCPAddr).Port)

	cfg := Config{
		CiliumApiTcpEnabled: true,
		CiliumApiTcpPort:    port,
	}
	lc := &mockLifecycle{}
	logger, hook := test.NewNullLogger()

	err = registerServer(lc, logger, nil, cfg)
	assert.NoError(t, err)

	assert.Len(t, lc.hooks, 1)
	if len(lc.hooks) == 0 {
		return
	}
	h := lc.hooks[0]

	// Start - should fail after retries
	// It should block for ~700ms (100+200+400)
	start := time.Now()
	err = h.Start(cell.HookContext(context.Background()))
	duration := time.Since(start)

	assert.NoError(t, err, "Should return nil even on failure")
	// Allow some buffer for execution time, but ensure it waited at least for the first retry
	assert.Greater(t, duration, 100*time.Millisecond, "Should have waited for retries")

	// Verify error log
	assert.Equal(t, logrus.ErrorLevel, hook.LastEntry().Level)
	assert.Contains(t, hook.LastEntry().Message, "Cilium TCP API server failed to listen after retries")
}
