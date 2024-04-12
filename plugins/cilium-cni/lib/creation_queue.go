// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package lib

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/client"
	"github.com/cilium/cilium/pkg/defaults"
	endpointid "github.com/cilium/cilium/pkg/endpoint/id"
	epqueue "github.com/cilium/cilium/pkg/gke/endpointqueue"
	"github.com/cilium/cilium/pkg/lock/lockfile"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

type CreationFallbackClient struct {
	logger       *logrus.Entry
	lockfile     *lockfile.Lockfile
	CiliumClient *client.Client
}

// the maximum number of queued creations allowed, to protect against kubelet insanity
const maxCreationFiles = 32

// Lock acquire timeout
const lockAcquireTimeout = 10 * time.Second

// timeout for connecting to agent fast start mode
const connectionTimeoutFastStart = 100 * time.Millisecond

func (c *CreationFallbackClient) tryConnect(timeout time.Duration) error {
	if dc, err := client.NewDefaultClientWithTimeout(timeout); err != nil {
		return err
	} else {
		c.CiliumClient = dc
		return nil
	}
}

// NewCreationFallbackClient creates a client that will either issue an EndpointCreate
// request via the api, *or* queue one in a temporary directory if fastStartEnabled is set.
func NewCreationFallbackClient(logger *logrus.Entry, fastStartEnabled bool) (*CreationFallbackClient, error) {
	fc := &CreationFallbackClient{
		logger: logger,
	}
	var timeout time.Duration

	if fastStartEnabled {
		timeout = connectionTimeoutFastStart
	} else {
		timeout = defaults.ClientConnectTimeout
	}

	// Try and connect (the usual case)
	err := fc.tryConnect(timeout)
	if err == nil {
		fc.logger.Info("NewCreationFallbackClient tryConnect() succeeded ")
		return fc, nil
	}

	if !fastStartEnabled {
		return nil, fmt.Errorf("agent is down: %w", err)
	}

	// We failed to connect. Acquire a shared queue lock for creation queue.
	if fc.lockfile, err = AcquireLock(epqueue.CreateQueueDir, epqueue.CreateQueueLockfile, SharedLock, lockAcquireTimeout); err != nil {
		return nil, fmt.Errorf("acquire creation queue lock: %w", err)
	}
	// We have the queue lock; try and connect again
	// just in case the agent finished starting up while we were waiting
	if err := fc.tryConnect(timeout); err == nil {
		fc.logger.Info("Successfully connected to API on second try.")
		// drop the lock as direct client (CiliumClient) will be used
		fc.lockfile.Unlock()
		fc.lockfile = nil
	}
	return fc, nil
}

// EndpointCreate creates an endpoint, either by directly accessing the API or dropping in a queued-creation file.
func (c *CreationFallbackClient) EndpointCreate(ep *models.EndpointChangeRequest) (*models.Endpoint, error) {
	if c.CiliumClient != nil {
		return c.CiliumClient.EndpointCreate(ep)
	}
	c.logger.WithField(logfields.ContainerID, ep.ContainerID).WithField(logfields.K8sPodName, ep.K8sPodName).Info("Queueing creation request for endpoint")

	if c.lockfile == nil {
		return nil, fmt.Errorf("attempt to create queue with no valid lockfile")
	}

	// Validity check: if there are too many queued creates, just return error
	// back up to the kubelet. If we get here, it's either because something
	// has gone wrong with the kubelet, or the agent has been down for a very
	// long time. To guard aganst long agent startup times (when it empties the
	// queue), limit us to 32 queued creations. If this does, indeed, overflow,
	// then the kubelet will get the failure and eventually retry creation.
	files, err := os.ReadDir(epqueue.CreateQueueDir)
	if err != nil {
		c.logger.WithField(logfields.Path, epqueue.CreateQueueDir).WithError(err).Error("list creation queue directory")
		return nil, err
	}
	numQueued := len(files)
	if numQueued > maxCreationFiles {
		return nil, fmt.Errorf("creation queue directory %s has too many entries(%d); aborting queueing", epqueue.CreateQueueDir, numQueued)
	}

	endpointId := endpointid.NewID(endpointid.ContainerIdPrefix, ep.ContainerID)

	// Prevent queueing both creation and deletion requests for the same container.
	// This is needed here to prevent having synchronization mechanisms in the
	// cilium agent to guarantee correct processing order for pod creation and deletion queues.
	removed := false
	if removed, err = DeleteFromQueueIfPresent(QueueFilename(endpointId, "delete"), defaults.DeleteQueueDir, defaults.DeleteQueueLockfile, lockAcquireTimeout); err != nil {
		return nil, fmt.Errorf("check delete queue before queueing create: %w", err)
	}
	if removed {
		c.logger.Warnf("delete was queued before create. Queued endpoint delete removed.")
	}
	b, err := ep.MarshalBinary()
	if err != nil {
		c.logger.WithField(logfields.ContainerID, ep.ContainerID).WithError(err).Error("write creation file")
		return nil, fmt.Errorf("write creation file: %w", err)
	}

	createEndpointPath := filepath.Join(epqueue.CreateQueueDir, QueueFilename(endpointId, "create"))
	err = os.WriteFile(createEndpointPath, b, 0644)
	if err != nil {
		c.logger.WithField(logfields.Path, createEndpointPath).WithError(err).Error("write creation file")
		return nil, fmt.Errorf("write creation file %s: %w", createEndpointPath, err)
	}
	c.logger.Infof("Wrote queued creation file %s", createEndpointPath)
	return nil, nil
}
