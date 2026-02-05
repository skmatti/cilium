// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Authors of Cilium
package queue

import (
	"context"

	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
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
	maxRetries     = 3
	baseRetryDelay = 2 * time.Second
	maxRetryDelay  = 300 * time.Second
)

var (
	log = logging.DefaultLogger.WithField(logfields.LogSubsys, "flow-trace-queue")
)

// FtKey is the key for a FlowTrace resource in the work queue.
type FtKey struct {
	Key       string
	OldFt     interface{}
	Operation Operation
}

// FtReconcileQueue is a rate-limiting queue for reconciling FlowTrace resources.
type FtReconcileQueue struct {
	name       string
	queue      workqueue.RateLimitingInterface
	maxRetries int
	sync       func(ctx context.Context, key FtKey) error
	workerDone chan struct{}
}

// NewFtReconcileQueue creates a new FlowTrace reconcile queue.
func NewFtReconcileQueue(queueName string, syncFn func(ctx context.Context, key FtKey) error) *FtReconcileQueue {
	queue := workqueue.NewNamedRateLimitingQueue(workqueue.NewItemExponentialFailureRateLimiter(baseRetryDelay, maxRetryDelay), queueName)
	return &FtReconcileQueue{
		name:       queueName,
		maxRetries: maxRetries,
		queue:      queue,
		sync:       syncFn,
		workerDone: make(chan struct{}),
	}
}

// Run starts the worker loop for the reconcile queue.
func (q *FtReconcileQueue) Run() {
	for {
		key, quit := q.queue.Get()
		if quit {
			log.Debugf("Queue shutdown, exiting worker %v", q.name)
			close(q.workerDone)
			return
		}
		ftKey := key.(FtKey)
		// TODO: Consider accepting a context in Run() from the caller
		if err := q.sync(context.TODO(), ftKey); err != nil {
			if q.queue.NumRequeues(key) < q.maxRetries {
				log.WithError(err).Errorf("Requeuing %s due to error", ftKey.Key)
				q.queue.AddRateLimited(key)
			} else {
				log.WithError(err).Errorf("Dropping %s from queue after %d retries", ftKey.Key, q.maxRetries)
				q.queue.Forget(key)
			}
		} else {
			q.queue.Forget(key)
		}
		q.queue.Done(key)
	}
}

// Enqueue adds a key to the work queue.
func (q *FtReconcileQueue) Enqueue(key FtKey) {
	log.Debugf("Enqueueing key=%q", key.Key)
	q.queue.Add(key)
}

// Shutdown shuts down the work queue and waits for the worker to finish.
func (q *FtReconcileQueue) Shutdown() {
	log.Info("Shutting down queue")
	q.queue.ShutDown()
	<-q.workerDone
}
