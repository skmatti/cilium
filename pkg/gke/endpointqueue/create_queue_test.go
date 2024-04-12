package endpointqueue

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/cilium/cilium/pkg/time"

	"github.com/cilium/cilium/api/v1/models"
	endpointid "github.com/cilium/cilium/pkg/endpoint/id"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/lock/lockfile"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/promise"
	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"
)

const (
	testCreateQueueDir      = "/tmp/createQueue"
	testCreateQueueLockfile = testCreateQueueDir + "/lockfile"
	testRetryAttempts       = 1
	testRetryInterval       = 1 * time.Second
)

type testDaemon struct {
	numEndpointsProcessed int
}

func (d *testDaemon) CreateEndpoint(ctx context.Context, endpoint *models.EndpointChangeRequest) error {
	if endpoint == nil {
		return fmt.Errorf("invalid endpoint")
	}
	d.numEndpointsProcessed++
	return nil
}

type CreateQueueTestSuite struct {
	hive *hive.Hive
	d    testDaemon
}

// newEndpointCreationSinkPromise converts a testDaemon promise into a EndpointCreationSink promise
func (k *CreateQueueTestSuite) newEndpointCreationSinkPromise(lc cell.Lifecycle) promise.Promise[EndpointCreationSink] {
	sResolver, sPromise := promise.New[EndpointCreationSink]()
	lc.Append(cell.Hook{
		OnStart: func(hc cell.HookContext) error {
			sResolver.Resolve(&k.d)
			return nil
		},
		OnStop: func(_ cell.HookContext) error {
			sResolver.Reject(fmt.Errorf("initialize endpoint creation sink"))
			return nil
		},
	})
	return sPromise

}

func (k *CreateQueueTestSuite) testQueuedEndpointCreationConfig() QueuedEndpointCreationConfig {
	return QueuedEndpointCreationConfig{
		createQueueDir:      testCreateQueueDir,
		createQueueLockfile: testCreateQueueLockfile,
		retryAttempts:       testRetryAttempts,
		retryInterval:       testRetryInterval,
	}
}

func (k *CreateQueueTestSuite) queueEndpoint(pod_name string) error {

	if err := os.MkdirAll(testCreateQueueDir, 0755); err != nil {
		return fmt.Errorf("ensure creation queue directory exists: %v", err)
	}

	ep := &models.EndpointChangeRequest{
		ContainerID:  pod_name,
		K8sPodName:   pod_name,
		K8sNamespace: "default",
	}

	b, err := ep.MarshalBinary()
	if err != nil {
		return fmt.Errorf("write creation file: %w", err)
	}

	id := endpointid.NewID(endpointid.ContainerIdPrefix, ep.ContainerID)
	h := sha256.New()
	h.Write([]byte(id))
	filename := fmt.Sprintf("%x.%s", h.Sum(nil), "create")
	path := filepath.Join(testCreateQueueDir, filename)

	if err = os.WriteFile(path, b, 0644); err != nil {
		return fmt.Errorf("write creation file %s: %w", path, err)
	}
	return nil
}

func pollCreateQueueDir(createQueueDir string, expectedNumFiles int, timeout time.Duration) error {
	start := time.Now()
	numFiles := 0
	for time.Since(start) < timeout {
		files, err := filepath.Glob(createQueueDir + "/*.create")
		if err != nil {
			return err
		}
		numFiles = len(files)
		if numFiles == expectedNumFiles {
			return nil
		}
		time.Sleep(time.Second * 1)
	}

	return fmt.Errorf("invalid number of files in %s. Expected: %d, Found: %d", createQueueDir, expectedNumFiles, numFiles)
}

func setupEndpointQueueTestSuite(tb testing.TB) *CreateQueueTestSuite {
	k := &CreateQueueTestSuite{}
	// clear the states
	k.d.numEndpointsProcessed = 0
	err := os.RemoveAll(testCreateQueueDir)
	require.Empty(tb, err)

	var epCell = cell.Module(
		"epqueue",
		"EpQueueCell",

		cell.Provide(k.newEndpointCreationSinkPromise),
		cell.Provide(k.testQueuedEndpointCreationConfig),
		metrics.Metric(newMetrics),
		cell.Invoke(createQueueManager),
	)
	k.hive = hive.New(epCell)
	return k
}

func TestCreateQueueDir(t *testing.T) {
	k := setupEndpointQueueTestSuite(t)

	tlog := hivetest.Logger(t)
	require.Empty(t, k.hive.Start(tlog, context.Background()))
	_, err := os.ReadDir(testCreateQueueDir)
	require.Empty(t, err)
	require.Empty(t, k.hive.Stop(tlog, context.Background()))
}

func TestQueuedProcessing(t *testing.T) {
	k := setupEndpointQueueTestSuite(t)
	k.queueEndpoint("ep1")
	k.queueEndpoint("ep2")

	tlog := hivetest.Logger(t)
	require.Empty(t, k.hive.Start(tlog, context.Background()))
	_, err := os.ReadDir(testCreateQueueDir)
	require.Empty(t, err)

	_, err = os.ReadFile(testCreateQueueLockfile)
	require.Empty(t, err)

	require.Empty(t, pollCreateQueueDir(testCreateQueueDir, 0, 10*time.Second))
	require.EqualValues(t, k.d.numEndpointsProcessed, 2)
	require.Empty(t, k.hive.Stop(tlog, context.Background()))
}

func TestCannotAcquireLock(t *testing.T) {
	k := setupEndpointQueueTestSuite(t)
	k.queueEndpoint("ep1")
	k.queueEndpoint("ep2")

	lf, err := lockfile.NewLockfile(testCreateQueueLockfile)
	require.Empty(t, err)
	defer lf.Close()
	err = lf.Lock(context.Background(), true)
	require.Empty(t, err)

	tlog := hivetest.Logger(t)
	// cannnot acquire lock and process endpoints as lock is already acquired in the test
	err = k.hive.Start(tlog, context.Background())
	require.NotEmpty(t, err)
	require.EqualValues(t, err.Error(), "lock queued creation directory: context deadline exceeded")
	require.Empty(t, k.hive.Stop(tlog, context.Background()))
}

func TestInvalidEndpointProcessing(t *testing.T) {
	k := setupEndpointQueueTestSuite(t)
	k.queueEndpoint("ep1")
	// queue an invalid create file
	path := filepath.Join(testCreateQueueDir, "invalid_ep.create")
	err := os.WriteFile(path, []byte("invalid_data"), 0644)
	require.Empty(t, err)

	tlog := hivetest.Logger(t)
	err = k.hive.Start(tlog, context.Background())
	require.NotEmpty(t, err)
	require.EqualValues(t, err.Error(), "queued endpoint processing incomplete")
	require.Empty(t, k.hive.Stop(tlog, context.Background()))

	_, err = os.ReadDir(testCreateQueueDir)
	require.Empty(t, err)

	_, err = os.ReadFile(testCreateQueueLockfile)
	require.Empty(t, err)

	// The invalid endpoint file is not deleted
	require.Empty(t, pollCreateQueueDir(testCreateQueueDir, 1, 10*time.Second))
	require.EqualValues(t, k.d.numEndpointsProcessed, 1)
}

func TestFileWatcherProcessing(t *testing.T) {
	k := setupEndpointQueueTestSuite(t)
	k.queueEndpoint("ep1")
	k.queueEndpoint("ep2")

	tlog := hivetest.Logger(t)
	require.Empty(t, k.hive.Start(tlog, context.Background()))
	_, err := os.ReadDir(testCreateQueueDir)
	require.Empty(t, err)

	_, err = os.ReadFile(testCreateQueueLockfile)
	require.Empty(t, err)

	require.Empty(t, pollCreateQueueDir(testCreateQueueDir, 0, 10*time.Second))
	require.EqualValues(t, k.d.numEndpointsProcessed, 2)

	// Queue more endpoint after inital processing and verify that they are processed by file watcher
	k.queueEndpoint("ep3")
	time.Sleep(100 * time.Millisecond)
	k.queueEndpoint("ep4")
	time.Sleep(100 * time.Millisecond)

	_, err = os.ReadFile(testCreateQueueLockfile)
	require.Empty(t, err)

	require.Empty(t, pollCreateQueueDir(testCreateQueueDir, 0, 10*time.Second))
	require.EqualValues(t, k.d.numEndpointsProcessed, 4)
	require.Empty(t, k.hive.Stop(tlog, context.Background()))
}
