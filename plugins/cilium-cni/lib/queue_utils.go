package lib

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/cilium/cilium/pkg/lock/lockfile"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

var (
	log = logging.DefaultLogger.WithField(logfields.LogSubsys, "cilium-cni")
)

// LockMode specifies whether to acquire the file lock in shared or exclusive mode.
type LockMode bool

const (
	SharedLock    LockMode = false
	ExclusiveLock LockMode = true
)

// AcquireLock acquires the lock (lockfileFullPath) in shared or exclusive mode.
// The lockfileDir and lockfileFullPath are created if its not already present.
// The responsibility of releasing the lock lies with the caller of this method.
func AcquireLock(lockfileDir, lockfileFullPath string, mode LockMode, timeout time.Duration) (*lockfile.Lockfile, error) {
	// Ensure queue directory exists, obtain shared lock
	if err := os.MkdirAll(lockfileDir, 0755); err != nil {
		return nil, fmt.Errorf("create queue directory %s: %w", lockfileDir, err)
	}

	lf, err := lockfile.NewLockfile(lockfileFullPath)
	if err != nil {
		return nil, fmt.Errorf("open lockfile %s: %w", lockfileFullPath, err)
	}

	ctx, cancel := context.WithTimeout(context.TODO(), timeout)
	defer cancel()

	if err := lf.Lock(ctx, bool(mode)); err != nil {
		return nil, fmt.Errorf("acquire lock %s: %w", lockfileFullPath, err)
	}
	return lf, nil
}

// Creates a queue filename consisting of a hashed container ID and the given suffix.
func QueueFilename(containerID, suffix string) string {
	h := sha256.New()
	h.Write([]byte(containerID))
	return fmt.Sprintf("%x.%s", h.Sum(nil), suffix)
}

func appendToFile(filePath string, content []byte) error {
	// Open the file in append mode.  Create it if it doesn't exist.
	file, err := os.OpenFile(filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer file.Close() // Important to close the file when done

	// Write the content to the file.
	_, err = file.Write(content)
	if err != nil {
		return err
	}
	return nil
}

func deleteFromQueueIfPresentLocked(epFileFullPath string) (bool, error) {
	if err := os.Remove(epFileFullPath); err != nil {
		if os.IsNotExist(err) {
			// A missing file means that the endpoint is not queued for creation or deletion.
			return false, nil
		}
		return false, fmt.Errorf("remove existing queued file %s: %w", epFileFullPath, err)
	}

	log.Logger.Info("Queued file removed: ", epFileFullPath)
	return true, nil
}

// DeleteFromQueueIfPresentLocked checks for the queued endpoint (epFileFullPath) and deletes it if present.
// Returns false if the endpoint was not queued.
// Returns true if the endpoint existed and was removed.
func DeleteFromQueueIfPresent(epFileName, queueDir, lockfileFullPath string, timeout time.Duration) (bool, error) {
	var err error
	var sharedLock *lockfile.Lockfile
	epFileFullPath := filepath.Join(queueDir, epFileName)
	if sharedLock, err = AcquireLock(queueDir, lockfileFullPath, SharedLock, timeout); err != nil {
		log.Logger.Infof("could not acquire shared lock %s:%v", lockfileFullPath, err)
		return false, err
	}
	defer sharedLock.Unlock()
	return deleteFromQueueIfPresentLocked(epFileFullPath)
}
