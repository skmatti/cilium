package wait

import (
	"context"
	"errors"
	"fmt"
	"time"

	klog "gke-internal.googlesource.com/syllogi/sanitized-klog/third_party/klogv2"
	"gke-internal.googlesource.com/third_party/cilium/google_test/wora/e2e/pkg/test/errorring"
)

// maxErrsRetained is the maximum number of errors that will be returned,
// including the most recent.
const maxErrsRetained = 6

var (
	// ErrNotRetriable is used to wrap errors that should not be retried by the
	// WaitForSuccess functions.
	ErrNotRetriable = errors.New("not retriable")
	// ErrExecutionTimeoutReached is returned when the user-provided function
	// times out on an individual run.
	ErrExecutionTimeoutReached = errors.New("WaitForSuccess function execution timeout reached")
	// ErrTotalTimeoutReached is returned when the total timeout has been
	// reached.
	ErrTotalTimeoutReached = errors.New("WaitForSuccess total timeout reached")
)

// Waiting defines the polling frequency and timeout for WaitForSuccess.
type Waiting struct {
	// Wait is when WaitForSuccess should give up.
	Wait time.Duration
	// Every is how often WaitForSuccess will wait between attempts.
	Every time.Duration
	// Timeout is how long each attempt should get. This is only supported in
	// WaitForSuccessContext and RetryOnErrorContext. The user-provided function
	// is responsible for respecting the timeout by handling ctx.Done()
	// properly.
	Timeout time.Duration
}

var (
	// WaitingShort is a 5 second timeout.
	WaitingShort = Waiting{
		Wait:    5 * time.Second,
		Every:   100 * time.Millisecond,
		Timeout: 5 * time.Second,
	}
	// WaitingMedium is a 1 minute timeout.
	WaitingMedium = Waiting{
		Wait:    1 * time.Minute,
		Every:   5 * time.Second,
		Timeout: 5 * time.Second,
	}
	// WaitingLong is a 5 minute timeout.
	WaitingLong = Waiting{
		Wait:    5 * time.Minute,
		Every:   5 * time.Second,
		Timeout: 1 * time.Minute,
	}
	// WaitingExtraLong is a 15 minute timeout.
	WaitingExtraLong = Waiting{
		Wait:    15 * time.Minute,
		Every:   30 * time.Second,
		Timeout: 1 * time.Minute,
	}
	// WaitingXXLong is a 30 minute timeout.
	WaitingXXLong = Waiting{
		Wait:    30 * time.Minute,
		Every:   30 * time.Second,
		Timeout: 1 * time.Minute,
	}
	// WaitingXXXLong is a 60 minute timeout.
	WaitingXXXLong = Waiting{
		Wait:    60 * time.Minute,
		Every:   30 * time.Second,
		Timeout: 1 * time.Minute,
	}
)

// updateEvery provides a rate limit on how often we're willing to log retries.
const updateEvery = 1 * time.Minute

// WaitForSuccess runs the user-provided function repeatedly until it returns no
// error or the given Wait time has been exceeded.
//
// Deprecated: Use WaitForSuccessContext instead.
//
// TODO(b/261681294): Migrate all usage to WaitForSuccessContext.
func WaitForSuccess(f func() error, wait Waiting, desc string) error {
	retriable := func(err error) bool {
		return !errors.Is(err, ErrNotRetriable)
	}
	if count, err := retryOnError(f, wait, desc, retriable); err != nil {
		return fmt.Errorf("[%s] WaitForSuccess gave up after %d tries: %w", desc, count, err)
	} else {
		klog.V(2).Infof("[%s] WaitForSuccess succeeded after %d tries", desc, count)
		return nil
	}
}

// WaitForSuccessContext runs the user-provided function repeatedly until:
// - It returns no error.
// - The given Wait time has been exceeded.
// - The context is done.
func WaitForSuccessContext(ctx context.Context, desc string, wait Waiting, f func(context.Context) error) error {
	// default duration of each attempt to the interval we want to perform attempts
	if wait.Timeout == 0 {
		wait.Timeout = wait.Every
	}
	retriable := func(err error) bool {
		// Context errors are retriable because we will be adding a timeout to
		// the inner context each time we run it.
		//
		// We will automatically exit when the outer context is done.
		return !errors.Is(err, ErrNotRetriable)
	}
	if count, err := RetryOnErrorContext(ctx, wait, desc, retriable, f); err != nil {
		return fmt.Errorf("[%s] WaitForSuccess gave up: %w", desc, err)
	} else {
		klog.V(2).Infof("[%s] WaitForSuccess succeeded after %d tries", desc, count)
		return nil
	}
}

// retryOnError runs the user-provided function repeatedly until:
// - It returns nil error or a non-retriable error.
// - The given Wait time has been exceeded.
//
// Returned int is the number of attempts.
func retryOnError(f func() error, wait Waiting, desc string, retriable func(error) bool) (int, error) {
	giveUp := time.Now().Add(wait.Wait)
	nextUpdate := time.Now().Add(updateEvery)
	klog.V(2).Infof("[%s] WaitForSuccess until %s, retry every %s", desc, giveUp, wait.Every)

	var err error
	var count int
	for time.Now().Before(giveUp) {
		if time.Now().After(nextUpdate) {
			klog.V(3).Infof("[%s] WaitForSuccess still retrying after %d tries. Last error: %s", desc, count, err)
			nextUpdate = time.Now().Add(updateEvery)
		}
		count++
		if err = f(); err != nil {
			if !retriable(err) {
				break
			}
			time.Sleep(wait.Every)
			continue
		}
		return count, nil
	}
	if err == nil {
		// Exceedingly unlikely, but in theory possible to have non-nil error.
		err = fmt.Errorf("no success, but also no error after waiting %s", wait.Wait)
	}
	return count, err
}

// RetryOnErrorContext runs the user-provided function repeatedly until one of
// the following cases happens:
// - It returns no error.
// - The given Wait time has been exceeded.
// - The context is done.
//
// If retriable is specified, it should consider context errors to be be
// retriable, as the context passed to the function will have a per-attempt
// timeout added.
//
// Returned int is the number of attempts.
//
// You should use WaitForSuccessContext instead, unless you need specific
// retriable errors.
func RetryOnErrorContext(ctx context.Context, wait Waiting, desc string, retriable func(error) bool, f func(ctx context.Context) error) (int, error) {
	if wait.Wait == 0 {
		return 0, fmt.Errorf("invalid argument: wait.Wait must be specified and non-zero: %w", ErrNotRetriable)
	}
	if wait.Every == 0 {
		return 0, fmt.Errorf("invalid argument: wait.Every must be specified and non-zero: %w", ErrNotRetriable)
	}
	if wait.Timeout == 0 {
		return 0, fmt.Errorf("invalid argument: wait.Timeout must be specified and non-zero: %w", ErrNotRetriable)
	}

	waitCtx, cancel := context.WithTimeout(ctx, wait.Wait)
	defer cancel()

	giveUp, _ := waitCtx.Deadline()
	klog.V(2).Infof("[%s] WaitForSuccess until %s, retry every %s", desc, giveUp, wait.Every)

	nextUpdate := time.Now().Add(updateEvery)
	update := func(msg string) {
		if now := time.Now(); now.After(nextUpdate) {
			klog.V(3).Info(msg)
			nextUpdate = now.Add(updateEvery)
		}
	}

	// Buffered so that the goroutine can exit even if this function has
	// returned.
	done := make(chan error, 1)
	errs, err := errorring.New(maxErrsRetained)
	if err != nil {
		return 0, err
	}
	for {
		// Start the every timer early so that we can account for the execution
		// time.
		every := time.After(wait.Every)

		// We base this context on the param ctx, not the waitCtx because we
		// don't want f() to return the waitCtx cancellation when it gives up.
		// If it did, we would not get to see the last real (non-timeout) error
		// returned by the function.
		cancelCtx, cancel := context.WithCancel(ctx)
		go func() {
			// Catch the panic to protect gpctest. If f() is allowed to panic in
			// a goroutine, gpctest would exit before cleaning up resources.
			defer func() {
				if r := recover(); r != nil {
					done <- fmt.Errorf("recovered from panic: %v: %w", r, ErrNotRetriable)
				}
			}()
			defer cancel()
			done <- f(cancelCtx)
		}()
		select {
		case err := <-done: // Function done.
			errs.Add(err)
			if err != nil && !retriable(err) {
				return errs.Count(), errs.Complete()
			}
			if err == nil {
				// Add one to count because errs.Count() does not track the successful attempt.
				return errs.Count() + 1, nil
			}

			update(fmt.Sprintf("[%s] WaitForSuccess still retrying: %v", desc, errs.Last()))
		case <-waitCtx.Done(): // Ctx done or we are giving up based on total time.
			cancel()
			err := fmt.Errorf("parent %s: %w", waitCtx.Err(), ErrTotalTimeoutReached)
			errs.Add(err)
			return errs.Count(), errs.Complete()
		case <-time.After(wait.Timeout): // Reached individual attempt timeout before func finished.
			cancel()
			// Ensure that we don't end up with multiple f() running in
			// parallel.
			select {
			case err := <-done:
				err = fmt.Errorf("%s: %w", err, ErrExecutionTimeoutReached)
				errs.Add(err)
			case <-waitCtx.Done():
				err := fmt.Errorf("parent %s: %w", waitCtx.Err(), ErrTotalTimeoutReached)
				errs.Add(err)
				return errs.Count(), errs.Complete()
			}
			update(fmt.Sprintf("[%s] WaitForSuccess still retrying: %v", desc, errs.Last()))
		}

		select {
		case <-every:
		case <-waitCtx.Done():
		}
	}
}

func ConsistentlySucceeds(f func() error, wait Waiting) error {
	giveUp := time.Now().Add(wait.Wait)
	for time.Now().Before(giveUp) {
		if err := f(); err != nil {
			return err
		}
		time.Sleep(wait.Every)
	}
	return nil
}
