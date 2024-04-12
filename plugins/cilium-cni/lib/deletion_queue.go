// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package lib

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
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

type DeletionFallbackClient struct {
	logger *logrus.Entry
	cli    *client.Client

	lockfile *lockfile.Lockfile
}

// the timeout for connecting and obtaining the lock
// the default of 30 seconds is too long; kubelet will time us out before then
const timeoutSeconds = 10

// the maximum number of queued deletions allowed, to protect against kubelet insanity
const maxDeletionFiles = 256

// NewDeletionFallbackClient creates a client that will either issue an EndpointDelete
// request via the api, *or* queue one in a temporary directory.
// To prevent race conditions, the logic is:
// 1. Try and connect to the socket. if that succeeds, done
// 2. Otherwise, take a shared lock on the delete queue directory
// 3. Once we get the lock, check to see if the socket now exists
// 4. If it exists, drop the lock and use the api
func NewDeletionFallbackClient(logger *logrus.Entry) (*DeletionFallbackClient, error) {
	dc := &DeletionFallbackClient{
		logger: logger,
	}

	// Try and connect (the usual case)
	err := dc.tryConnect()
	if err == nil {
		return dc, nil
	}
	dc.logger.WithError(err).Warnf("Failed to connect to agent socket at %s.", client.DefaultSockPath())

	// We failed to connect:acquire a shared queue lock
	if dc.lockfile, err = AcquireLock(defaults.DeleteQueueDir, defaults.DeleteQueueLockfile, SharedLock, lockAcquireTimeout); err != nil {
		return nil, fmt.Errorf("failed to acquire deletion queue: %w", err)
	}

	// We have the queue lock; try and connect again
	// just in case the agent finished starting up while we were waiting
	if err := dc.tryConnect(); err == nil {
		dc.logger.Info("Successfully connected to API on second try.")
		// hey, it's back up!
		dc.lockfile.Unlock()
		dc.lockfile = nil
		return dc, nil
	}

	// We have the lockfile, but no valid client
	dc.logger.Info("Agent is down, falling back to deletion queue directory")
	return dc, nil
}

func (dc *DeletionFallbackClient) tryConnect() error {
	c, err := client.NewDefaultClientWithTimeout(timeoutSeconds * time.Second)
	if err != nil {
		return err
	}
	dc.cli = c
	return nil
}

// EndpointDelete deletes an endpoint given by an endpoint id, either
// by directly accessing the API or dropping in a queued-deletion file.
// endpoint-id is a qualified endpoint reference, e.g. "container-id:XXXXXXX"
func (dc *DeletionFallbackClient) EndpointDelete(id string) error {
	if dc.cli != nil {
		return dc.cli.EndpointDelete(id)
	}

	// fall-back mode
	if dc.lockfile != nil {
		dc.logger.WithField(logfields.EndpointID, id).Info("Queueing deletion request for endpoint")
		return dc.enqueueDeletionRequestLocked(id, id)

	}

	return errors.New("attempt to delete with no valid connection")
}

// EndpointDeleteMany deletes multiple endpoints based on the endpoint deletion request,
// either by directly accessing the API or dropping in a queued-deletion file.
func (dc *DeletionFallbackClient) EndpointDeleteMany(req *models.EndpointBatchDeleteRequest) error {
	if dc.cli != nil {
		err := dc.cli.EndpointDeleteMany(req)
		if err == nil || (err != nil && !strings.Contains(err.Error(), "deleteEndpointNotFound")) {
			return err
		}

		dc.logger.WithField(logfields.Request, req).WithError(err).Info("Unable to delete cilium endpoint.")
		endpointId := endpointid.NewID(endpointid.ContainerIdPrefix, req.ContainerID)
		removed, innerErr := DeleteFromQueueIfPresent(QueueFilename(endpointId, "create"), epqueue.CreateQueueDir, epqueue.CreateQueueLockfile, lockAcquireTimeout)
		if innerErr != nil {
			return errors.Join(err, innerErr)
		}
		if removed {
			dc.logger.WithField(logfields.EndpointID, endpointId).Infof("Unprocessed create queue entry was found and deleted")
			return nil
		}
		return err
	}

	// fall-back mode
	if dc.lockfile != nil {
		dc.logger.WithField(logfields.Request, req).Info("Queueing endpoint batch deletion request")
		b, err := req.MarshalBinary()
		if err != nil {
			return fmt.Errorf("failed to marshal endpoint delete request: %w", err)
		}
		return dc.enqueueDeletionRequestLocked(string(b), endpointid.NewID(endpointid.ContainerIdPrefix, req.ContainerID))
	}

	return errors.New("attempt to delete with no valid connection")
}

// enqueueDeletionRequestLocked enqueues the encoded endpoint deletion request into the
// endpoint deletion queue. Requires the caller to hold the deletion queue lock.
func (dc *DeletionFallbackClient) enqueueDeletionRequestLocked(contents string, endpointId string) error {
	// Validity check: if there are too many queued deletes, just return error
	// back up to the kubelet. If we get here, it's either because something
	// has gone wrong with the kubelet, or the agent has been down for a very
	// long time. To guard against long agent startup times (when it empties the
	// queue), limit us to 256 queued deletions. If this does, indeed, overflow,
	// then the kubelet will get the failure and eventually retry deletion.
	files, err := os.ReadDir(defaults.DeleteQueueDir)
	if err != nil {
		dc.logger.WithField(logfields.Path, defaults.DeleteQueueDir).WithError(err).Error("failed to list deletion queue directory")
		return err
	}
	if len(files) > maxDeletionFiles {
		return fmt.Errorf("deletion queue directory %s has too many entries; aborting", defaults.DeleteQueueDir)
	}

	// Prevent queueing both creation and deletion requests for the same pod.
	// This is needed here to prevent having synchronization mechanisms in the
	// cilium agent to guarantee correct processing order for pod creation and deletion queues.
	removed := false
	if removed, err = DeleteFromQueueIfPresent(QueueFilename(endpointId, "create"), epqueue.CreateQueueDir, epqueue.CreateQueueLockfile, lockAcquireTimeout); err != nil {
		return fmt.Errorf("check create queue before queueing delete: %w", err)
	}
	if removed {
		dc.logger.WithField(logfields.EndpointID, endpointId).Infof("Unprocessed queued create found for the same container. Removing it and skipping delete.")
		return nil
	}

	deleteEndpointPath := filepath.Join(defaults.DeleteQueueDir, QueueFilename(endpointId, "delete"))
	err = os.WriteFile(deleteEndpointPath, []byte(contents), 0644)
	if err != nil {
		dc.logger.WithField(logfields.Path, deleteEndpointPath).WithError(err).Error("failed to write deletion file")
		return fmt.Errorf("failed to write deletion file %s: %w", deleteEndpointPath, err)
	}
	dc.logger.WithField(logfields.EndpointID, endpointId).Info("wrote queued deletion file")
	return nil
}
