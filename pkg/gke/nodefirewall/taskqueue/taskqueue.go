/*
Copyright 2020 Google LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package taskqueue

import (
	"time"

	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"

	"github.com/cilium/cilium/pkg/gke/nodefirewall/logging"
)

var (
	keyFunc = cache.DeletionHandlingMetaNamespaceKeyFunc
)

const (
	maxRetries = 10
	// baseRetryDelay and maxRetryDelay are the parameters for exponential back-off on failures.
	baseRetryDelay = 2 * time.Second
	maxRetryDelay  = 300 * time.Second
)

// TaskQueue is a rate limited operation queue.
type TaskQueue interface {
	Run()
	Enqueue(objs ...interface{})
	Shutdown()
}

// PeriodicTaskQueue invokes the given sync function for every work item
// inserted. If the sync() function results in an error, the item is put on
// the work queue after a rate-limit.
type PeriodicTaskQueue struct {
	// resource is used for logging to distinguish the queue being used.
	resource string
	// keyFunc translates an object to a string-based key.
	keyFunc func(obj interface{}) (string, error)
	// queue is the work queue the worker polls.
	queue workqueue.RateLimitingInterface
	// maxRetries is the maximum number of sync retries for a policy.
	// Policy is evicted from the queue after these many retries.
	maxRetries int
	// sync is called for each item in the queue.
	sync func(string) error
	// workerDone is closed when the worker exits.
	workerDone chan struct{}
}

// Run the task queue. This will block until the Shutdown() has been called.
func (t *PeriodicTaskQueue) Run() {
	for {
		key, quit := t.queue.Get()
		if quit {
			logging.NodeFWLogger.Debugf("Queue shutdown, exiting worker (%v)", t.resource)
			close(t.workerDone)
			return
		}
		logging.NodeFWLogger.Debugf("Syncing %v (%v)", key, t.resource)
		if err := t.sync(key.(string)); err != nil {
			if t.queue.NumRequeues(key) < t.maxRetries {
				logging.NodeFWLogger.Errorf("Requeuing %q due to error: %v (%v)", key, err, t.resource)
				t.queue.AddRateLimited(key)
			} else {
				logging.NodeFWLogger.Errorf("Dropping %q out of the queue, sync failed in %d retries: %v (%v)", key, t.maxRetries, err, t.resource)
				t.queue.Forget(key)
			}
		} else {
			logging.NodeFWLogger.Debugf("Finished syncing %v", key)
			t.queue.Forget(key)
		}
		t.queue.Done(key)
	}
}

// Enqueue one or more keys to the work queue.
func (t *PeriodicTaskQueue) Enqueue(objs ...interface{}) {
	for _, obj := range objs {
		key, err := t.keyFunc(obj)
		if err != nil {
			logging.NodeFWLogger.Errorf("Couldn't get key for object %+v (type %T): %v", obj, obj, err)
			return
		}
		logging.NodeFWLogger.Debugf("Enqueue key=%q (%v)", key, t.resource)
		t.queue.Add(key)
	}
}

// Shutdown shuts down the work queue and waits for the worker to ACK
func (t *PeriodicTaskQueue) Shutdown() {
	logging.NodeFWLogger.Infof("Shutdown")
	t.queue.ShutDown()
	<-t.workerDone
}

// NewPeriodicTaskQueue creates a new task queue with the default rate limiter.
func NewPeriodicTaskQueue(resource string, syncFn func(string) error) *PeriodicTaskQueue {
	queue := workqueue.NewNamedRateLimitingQueue(workqueue.NewItemExponentialFailureRateLimiter(baseRetryDelay, maxRetryDelay), resource)

	return &PeriodicTaskQueue{
		resource:   resource,
		keyFunc:    keyFunc,
		maxRetries: maxRetries,
		queue:      queue,
		sync:       syncFn,
		workerDone: make(chan struct{}),
	}
}
