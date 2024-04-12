package endpointqueue

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/time"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/lock/lockfile"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/promise"
	"github.com/cilium/hive/cell"
	"github.com/fsnotify/fsnotify"
)

const (
	// CreateQueueDir is the directory used for the CNI plugin to queue
	// creation requests if the agent is not up
	CreateQueueDir = defaults.RuntimePath + "/createQueue"
	// CreateQueueLockfile is the file used to synchronize access of the
	// CreateQueueDir directory between the agent and the CNI plugin processes
	CreateQueueLockfile = CreateQueueDir + "/lockfile"

	// Number of attempts to retry an endpoint creation failure
	retryAttempts = 5
	// Time interval between successive retries
	retryInterval = 1 * time.Second

	createQueueSubsys = "createQueue"
)

type QueuedEndpointCreationConfig struct {
	createQueueDir      string
	createQueueLockfile string
	retryAttempts       int
	retryInterval       time.Duration
}

var (
	log = logging.DefaultLogger.WithField(logfields.LogSubsys, createQueueSubsys)
)

type createEpQueueParams struct {
	cell.In

	Lifecycle cell.Lifecycle
	EpPromise promise.Promise[EndpointCreationSink]
	Config    QueuedEndpointCreationConfig
	Metrics   createQueueMetrics
}

var Cell = cell.Module(
	"create-queued-eps",
	"Create queued endpoints",
	cell.Provide(queuedEndpointCreationConfig),
	metrics.Metric(newMetrics),
	cell.Invoke(createQueueManager),
)

type EndpointCreationSink interface {
	CreateEndpoint(ctx context.Context, endpoint *models.EndpointChangeRequest) error
}

func queuedEndpointCreationConfig() QueuedEndpointCreationConfig {
	return QueuedEndpointCreationConfig{
		createQueueDir:      CreateQueueDir,
		createQueueLockfile: CreateQueueLockfile,
		retryAttempts:       retryAttempts,
		retryInterval:       retryInterval,
	}
}

func createQueueManager(params createEpQueueParams) error {
	if err := os.MkdirAll(params.Config.createQueueDir, 0755); err != nil {
		return fmt.Errorf("ensure creation queue directory exists: %v", err)
	}
	log.Infof("Creation queue directory exists at %s", params.Config.createQueueDir)

	watcherCtx, cancelWatcherCtx := context.WithCancel(context.Background())
	var watcher *fsnotify.Watcher

	params.Lifecycle.Append(cell.Hook{
		OnStart: func(ctx cell.HookContext) error {
			s, err := params.EpPromise.Await(ctx)
			if err != nil {
				return fmt.Errorf("get endpoint creation sink: %v", err)
			}
			if err := processCreateQueue(ctx, s, params.Config, params.Metrics, reconcileTypeStartup); err != nil {
				return err
			}

			// Endpoint creation requests should not be queued by cilium-cni after it can connect
			// to cilium agent. However the request can still be queued in case connection between cni and agent fails
			// or timesout for some reason.
			// Create a file system watcher to process queued endpoints after cilium agent is up.
			watcher, err = fsnotify.NewWatcher()
			if err != nil {
				return fmt.Errorf("create fsnotify watcher: %s", err)
			}

			if err = watcher.Add(params.Config.createQueueDir); err != nil {
				watcher.Close()
				return fmt.Errorf("add %s dir to fsnotify watcher: %s", params.Config.createQueueDir, err)
			}

			go func() {
				watchCreateQueueDir(watcherCtx, watcher, s, params.Config, params.Metrics, reconcileTypeFileNotify)
			}()

			return nil
		},
		OnStop: func(cell.HookContext) error {
			if watcher != nil {
				watcher.Close()
			}
			cancelWatcherCtx()
			return nil
		},
	})
	return nil
}

func watchCreateQueueDir(ctx context.Context, watcher *fsnotify.Watcher, s EndpointCreationSink, config QueuedEndpointCreationConfig, metrics createQueueMetrics, reconcileType string) {
	if watcher == nil {
		log.Error("Invalid create queue dir watcher")
		return
	}
	for {
		select {
		case event, ok := <-watcher.Events:
			if !ok {
				log.Infof("Create fsnotify watcher channel closed")
				return
			}
			if (event.Op & fsnotify.Create) == fsnotify.Create {
				log.Infof("New create queue file notification: %s", event.Name)
				if err := processCreateQueue(ctx, s, config, metrics, reconcileType); err != nil {
					log.WithError(err).Warn("Cannot process create queue notification")
				}
			}
		case err, ok := <-watcher.Errors:
			if !ok {
				log.Infof("Create fsnotify watcher channel closed")
				return
			}
			log.WithError(err).Warn("Watcher received an error")
		}
	}
}

func getQueuedEndpointFileList(ctx context.Context, lf *lockfile.Lockfile, createQueueDir string) ([]string, error) {
	if err := lf.Lock(ctx, true); err != nil {
		return nil, fmt.Errorf("lock queued creation directory: %w", err)
	}
	defer lf.Unlock()
	log.WithField(logfields.Path, createQueueDir).Infof("Locked creation queue directory to get queued endpoint files")
	return filepath.Glob(createQueueDir + "/*.create")
}

func processCreateQueue(ctx context.Context, s EndpointCreationSink, config QueuedEndpointCreationConfig, metrics createQueueMetrics, reconcileType string) error {

	lf, err := lockfile.NewLockfile(config.createQueueLockfile)
	if err != nil {
		return fmt.Errorf("create lockfile for creation queue: %v", err)
	}
	defer lf.Close()
	log.Infof("Creation queue lockfile exists at %s", config.createQueueLockfile)

	for attempt := 0; attempt < config.retryAttempts; attempt++ {
		// timeout for acquiring the lock and processing all the queued endpoints requests
		queueProcessingCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		log.Infof("Creating queued endpoints. Attempt: %d", attempt)
		if err = createQueuedEndpoints(queueProcessingCtx, lf, config.createQueueDir, s, metrics, reconcileType); err == nil {
			return nil
		}
		time.Sleep(config.retryInterval)
	}

	lockCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	epQueueFiles, err := getQueuedEndpointFileList(lockCtx, lf, config.createQueueDir)
	if err != nil {
		return err
	}
	unprocessedCnt := len(epQueueFiles)
	if unprocessedCnt > 0 {
		metrics.ReconcileTotal.WithLabelValues(reconcileType, labelValueOutcomeFail).Add(float64(unprocessedCnt))
		return fmt.Errorf("queued endpoint processing incomplete")
	}
	return nil
}

func createQueuedEndpoints(ctx context.Context, lf *lockfile.Lockfile, createQueueDir string, s EndpointCreationSink, metrics createQueueMetrics, reconcileType string) error {

	epQueueFiles, err := getQueuedEndpointFileList(ctx, lf, createQueueDir)
	if err != nil {
		return err
	}

	failed := 0
	for _, epFile := range epQueueFiles {
		if err := createEndpointFromFile(ctx, lf, s, epFile); err != nil {
			failed++
			log.WithError(err).WithField(logfields.Path, epFile).Error("Failed to create endpoint.")
		} else {
			log.Infof("Incrementing metric %p", &metrics.ReconcileTotal)
			metrics.ReconcileTotal.WithLabelValues(reconcileType, labelValueOutcomeSuccess).Inc()
		}
	}

	if failed > 0 {
		return fmt.Errorf("creation failed for %d queued endpoints", failed)
	}
	return nil
}

func createEndpointFromFile(ctx context.Context, lf *lockfile.Lockfile, s EndpointCreationSink, epFile string) error {
	log.Infof("Processing queued endpoint creation request: %s", epFile)

	if err := lf.Lock(ctx, true); err != nil {
		return fmt.Errorf("lock queued creation directory: %v", err)
	}
	defer lf.Unlock()
	log.Infof("Locked creation queue directory to process queued endpoint file %s", epFile)

	b, err := os.ReadFile(epFile)
	if err != nil {
		if os.IsNotExist(err) {
			log.Infof("Queued endpoint file %s no longer exists", epFile)
			// A missing file means that the queued endpoint is removed by a CNI DEL before we processed create endpoint
			return nil
		}
		return fmt.Errorf("read queued endpoint creation entry: %v", err)
	}
	ep := models.EndpointChangeRequest{}
	err = ep.UnmarshalBinary(b)
	if err != nil {
		return fmt.Errorf("unmarshal endpoint creation entry: %v", err)
	}

	log.Infof("Creating endpoint for %s/%s", ep.K8sNamespace, ep.K8sPodName)
	ep.SyncBuildEndpoint = false
	if err := s.CreateEndpoint(ctx, &ep); err != nil {
		return fmt.Errorf("queued endpoint creation for %s/%s: %v", ep.K8sNamespace, ep.K8sPodName, err)
	}

	if err := os.Remove(epFile); err != nil {
		log.WithError(err).WithField(logfields.Path, epFile).Error("Failed to remove queued endpoint creation entry, but creation was successful.")
	}
	return nil
}
