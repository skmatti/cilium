package lib

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cilium/cilium/pkg/lock/lockfile"
)

const (
	testLockTimeout = 2 * time.Second
)

func TestAcquireLockExclusive(t *testing.T) {
	testQueueDir := t.TempDir()
	testQueueLockfile := testQueueDir + "/lockfile"

	lf, err := AcquireLock(testQueueDir, testQueueLockfile, ExclusiveLock, testLockTimeout)
	if err != nil {
		t.Fatalf("Acquire lock: %v", err)
	}

	// It should not be possible to acquire the same lock again in exclusive mode.
	if _, err := AcquireLock(testQueueDir, testQueueLockfile, ExclusiveLock, testLockTimeout); err == nil {
		t.Fatalf("Expect error: acquire lock context deadline exceeded")
	}

	// It should not be possible to acquire the same lock again in shared mode.
	if _, err := AcquireLock(testQueueDir, testQueueLockfile, SharedLock, testLockTimeout); err == nil {
		t.Fatalf("Expect error: acquire lock context deadline exceeded")
	}

	lf.Unlock()
	if _, err := AcquireLock(testQueueDir, testQueueLockfile, true, testLockTimeout); err != nil {
		t.Fatalf("Re-acquire lock: %v", err)
	}
}

func TestAcquireLockShared(t *testing.T) {
	testQueueDir := t.TempDir()
	testQueueLockfile := testQueueDir + "/lockfile"

	lf, err := AcquireLock(testQueueDir, testQueueLockfile, SharedLock, testLockTimeout)
	if err != nil {
		t.Fatalf("Acquire lock: %v", err)
	}

	// It should be possible to acquire the same lock in shared mode.
	if _, err := AcquireLock(testQueueDir, testQueueLockfile, SharedLock, testLockTimeout); err != nil {
		t.Fatalf("Acquire lock: %v", err)
	}

	// It should not be possible to acquire the same lock in exclusive mode.
	if _, err := AcquireLock(testQueueDir, testQueueLockfile, ExclusiveLock, testLockTimeout); err == nil {
		t.Fatalf("Acquire lock: %v", err)
	}
	lf.Unlock()
}

func TestDeleteFromQueue(t *testing.T) {
	testQueueDir := t.TempDir()
	var err error
	var removed bool

	// create placeholder files
	epFilename1 := fmt.Sprintf("%s.%s", "ep1", "create")
	if err := os.WriteFile(filepath.Join(testQueueDir, epFilename1), []byte("some data"), 0644); err != nil {
		t.Fatalf("Create queue file: %v", err)
	}

	epFilename2 := fmt.Sprintf("%s.%s", "ep2", "create")
	if err := os.WriteFile(filepath.Join(testQueueDir, epFilename2), []byte("some data"), 0644); err != nil {
		t.Fatalf("Create queue file: %v", err)
	}

	epFilename3 := fmt.Sprintf("%s.%s", "ep3", "create")

	sharedLock := SharedLock
	exclusiveLock := ExclusiveLock
	var lf *lockfile.Lockfile
	testQueueLockfile := testQueueDir + "/lockfile"

	var deleteFromQueueTests = []struct {
		name                    string
		epFilename              string
		removed                 bool
		acquireLockBeforeDelete bool
		lockMode                *LockMode
		err                     error
	}{
		{"file not present no lock held", epFilename3, false, false, nil, nil},
		{"file not present shared lock held", epFilename3, false, true, &sharedLock, nil},
		{"file not present exclusive lock held", epFilename3, false, true, &exclusiveLock, fmt.Errorf("context deadline exceeded")},
		{"file present lock not held", epFilename1, true, false, nil, nil},
		{"file present shared lock held", epFilename2, true, true, &sharedLock, nil},
		{"file present exclusive lock held", epFilename2, false, true, &exclusiveLock, fmt.Errorf("context deadline exceeded")},
	}

	for _, tt := range deleteFromQueueTests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.acquireLockBeforeDelete {
				if lf, err = AcquireLock(testQueueDir, testQueueLockfile, *tt.lockMode, testLockTimeout); err != nil {
					t.Fatalf("Acquire lock: %v", err)
				}
			}
			if removed, err = DeleteFromQueueIfPresent(tt.epFilename, testQueueDir, testQueueLockfile, testLockTimeout); !errors.Is(err, tt.err) && !strings.Contains(err.Error(), tt.err.Error()) {
				t.Fatalf("DeleteFromQueueIfPresent result: expected: %v, got: %v", tt.err, err)
			}
			if removed != tt.removed {
				t.Fatalf("DeleteFromQueueIfPresent remove result: expected: %v, got: %v", tt.removed, removed)
			}
			if tt.acquireLockBeforeDelete && lf != nil {
				lf.Unlock()
			}
		})
	}
}
