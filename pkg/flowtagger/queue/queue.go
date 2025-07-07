package queue

import (
	"github.com/cilium/cilium/pkg/flowtagger/logging"
	"github.com/cilium/cilium/pkg/time"
	"k8s.io/client-go/util/workqueue"
)

type Operation string

const (
	CREATE Operation = "create"
	UPDATE Operation = "update"
	DELETE Operation = "delete"
)

const (
	maxRetries = 10
	// baseRetryDelay and maxRetryDelay are the parameters for exponential back-off on failures.
	baseRetryDelay = 2 * time.Second
	maxRetryDelay  = 300 * time.Second
)

type FtKey struct {
	Key       string
	OldFt     interface{}
	Operation Operation
}

type FtReconcileQueue struct {
	name    string
	keyFunc func(old, cur interface{}, operation Operation) (string, error)
	// queue is the work queue
	queue workqueue.RateLimitingInterface
	// maxRetries is the maximum number of sync retries for a FlowTagger.
	// FlowTagger is evicted from the queue after these many retries.
	maxRetries int
	// workerDone is closed when the worker exits.
	sync       func(key FtKey) error
	workerDone chan struct{}
}

func (q *FtReconcileQueue) Run() {
	for {
		key, quit := q.queue.Get()
		if quit {
			logging.FtLogger.Debugf("Queue shutdown, exiting worker %v", q.name)
			close(q.workerDone)
			return
		}
		logging.FtLogger.Debugf("Syncing %v (%v)", key, q.name)
		ftKey := key.(FtKey)
		if err := q.sync(ftKey); err != nil {
			if q.queue.NumRequeues(key) < q.maxRetries {
				logging.FtLogger.Errorf("Requeuing %s due to error: %v (%v)", ftKey.Key, err, q.name)
				logging.FtLogger.Debugf("Requeuing %q due to error: %v (%v)", ftKey, err, q.name) // debug log for detailed info about ftKey
				q.queue.AddRateLimited(key)
			} else {
				logging.FtLogger.Errorf("Dropping %s out of the queue, sync failed in %d retries: %v (%v)", ftKey.Key, q.maxRetries, err, q.name)
				logging.FtLogger.Debugf("Dropping %q out of the queue, sync failed in %d retries: %v (%v)", ftKey, q.maxRetries, err, q.name) // debug log for detailed info about ftKey
				q.queue.Forget(key)
			}
		} else {
			logging.FtLogger.Debugf("Finished syncing %v (%v)", ftKey.Key, q.name)
			q.queue.Forget(key)
		}
		q.queue.Done(key)
	}
}

// Enqueue one key to the work queue.
func (q *FtReconcileQueue) Enqueue(key FtKey) {
	logging.FtLogger.Debugf("Enqueue key=%q (%v)", key, q.name)
	q.queue.AddRateLimited(key)
}

// Enqueue one key to the work queue after the provide duration has passed.
func (q *FtReconcileQueue) EnqueueAfter(key FtKey, duration time.Duration) {
	logging.FtLogger.Debugf("Enqueue key=%q (%v)", key, q.name)
	q.queue.AddAfter(key, duration)
}

// Shutdown shuts down the work queue and waits for the worker to ACK
func (q *FtReconcileQueue) Shutdown() {
	logging.FtLogger.Infof("Shutdown")
	q.queue.ShutDown()
	<-q.workerDone
}

// NewFtReconcileQueue creates a new task queue with the default rate limiter.
func NewFtReconcileQueue(queueName string, syncFn func(FtKey) error) *FtReconcileQueue {
	queue := workqueue.NewNamedRateLimitingQueue(workqueue.NewItemExponentialFailureRateLimiter(baseRetryDelay, maxRetryDelay), queueName)

	return &FtReconcileQueue{
		name:       queueName,
		maxRetries: maxRetries,
		queue:      queue,
		sync:       syncFn,
		workerDone: make(chan struct{}),
	}
}
