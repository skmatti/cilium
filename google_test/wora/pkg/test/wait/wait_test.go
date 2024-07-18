package wait

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

// TestWaitForSuccessContext tests that WaitForSuccessContext properly handles
// some simple success conditions.
func TestWaitForSuccessContext(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)

	tcs := []struct {
		name string
		desc string
		f    func(context.Context) error
	}{
		{
			name: "immediate success",
			desc: "With instant readiness",
			f:    delaySuccessFunc(0, 0),
		},
		{
			name: "delayed success",
			desc: "With short ready time",
			f:    delaySuccessFunc(0, 2*time.Second),
		},
		{
			name: "sleep",
			desc: "With short initial sleep, but instant readiness",
			f:    delaySuccessFunc(500*time.Millisecond, 0),
		},
		{
			name: "sleep and delayed success",
			desc: "With short initial sleep and ready time",
			f:    delaySuccessFunc(500*time.Millisecond, 2*time.Second),
		},
	}

	for _, tc := range tcs {
		tc := tc // Capture for t.Parallel.
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			err := WaitForSuccessContext(ctx, "WaitForSuccess", testWait, tc.f)
			if err != nil {
				t.Fatalf("%s: WaitForSuccessContext returned unexpected error: %s", tc.desc, err)
			}
		})
	}
}

// TestWaitForSuccessContextErrors tests that WaitForSuccessContext properly
// handles some simple error conditions.
func TestWaitForSuccessContextErrors(t *testing.T) {
	tcs := []struct {
		name            string
		desc            string
		f               func(context.Context) error
		wantErrContains string
	}{
		{
			name:            "always fail",
			desc:            "With ready time of one hour",
			f:               delaySuccessFunc(0, time.Hour),
			wantErrContains: "not ready",
		},
		{
			name:            "always timeout",
			desc:            "With initial delay time of one hour, but instant readiness",
			f:               delaySuccessFunc(1*time.Hour, 0),
			wantErrContains: "parent context deadline",
		},
		{
			name:            "always timeout and fail",
			desc:            "With initial delay time of one hour and always failing",
			f:               delaySuccessFunc(1*time.Hour, 1*time.Hour),
			wantErrContains: "parent context deadline",
		},
	}

	for _, tc := range tcs {
		tc := tc // Capture for t.Parallel.
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			t.Cleanup(cancel)

			err := WaitForSuccessContext(ctx, "WaitForSuccess", testWait, tc.f)
			t.Logf("WaitForSuccessContext output (not an actual failure):\n%s", err)

			if !strings.Contains(err.Error(), tc.wantErrContains) {
				t.Fatalf("%s: WaitForSuccessContext error = %v; want contains %q", tc.desc, err, tc.wantErrContains)
			}
		})
	}
}

// This test validates WaitForSuccessContext errors based on invalid arguments.
func TestWaitForSuccessContextInvalidArguments(t *testing.T) {
	tcs := []struct {
		name            string
		wait            Waiting
		wantErrContains string
	}{
		{
			name: "missing wait.Wait",
			wait: Waiting{
				Wait:    0,
				Every:   1 * time.Second,
				Timeout: 1 * time.Second,
			},
			wantErrContains: "wait.Wait",
		},
		{
			name: "missing wait.Every",
			wait: Waiting{
				Wait:    1 * time.Second,
				Every:   0,
				Timeout: 1 * time.Second,
			},
			wantErrContains: "wait.Every",
		},
	}

	for _, tc := range tcs {
		tc := tc // Capture for t.Parallel.
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			t.Cleanup(cancel)

			err := WaitForSuccessContext(ctx, "WaitForSuccess", tc.wait, immediateSuccessFunc)
			t.Logf("WaitForSuccessContext output (not an actual failure):\n%s", err)

			if !strings.Contains(err.Error(), tc.wantErrContains) {
				t.Errorf("With %s: WaitForSuccessContext error = %q; did not contain %q", tc.name, err, tc.wantErrContains)
			}

			wantErr := ErrNotRetriable
			if diff := cmp.Diff(err, wantErr, cmpopts.EquateErrors()); diff != "" {
				t.Errorf("With %s: WaitForSuccessContext error did not derive from ErrNotRetriable (-got, +want):\n%s", tc.name, diff)
			}
		})
	}
}

// TestWaitForSuccessContextWithoutRespectingContext tests whether
// WaitForSuccessContext will return within the expected Wait time, regardless
// of whether f() respects the context that is passed to it.
func TestWaitForSuccessContextWithoutRespectingContext(t *testing.T) {
	t.Parallel()

	outsideCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)

	blockForever := func(context.Context) error {
		<-outsideCtx.Done()
		return fmt.Errorf("outside context cancelled")
	}

	err := WaitForSuccessContext(outsideCtx, "WaitForSuccess", testWait, blockForever)
	t.Logf("WaitForSuccessContext output (not an actual failure):\n%s", err)
	if err == nil {
		t.Fatalf("WaitForSuccessContext expected an error but returned success")
	}

	if err := outsideCtx.Err(); err != nil {
		t.Fatalf("WaitForSuccessContext didn't return until parent context timed out")
	}
}

// TestWaitForSuccessContextWithPanic tests whether WaitForSuccessContext
// properly recovers from a function which panics.
func TestWaitForSuccessContextWithPanic(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)

	want := "panic!"
	panicFunc := func(context.Context) error {
		panic(want)
	}

	err := WaitForSuccessContext(ctx, "WaitForSuccess", testWait, panicFunc)
	t.Logf("WaitForSuccessContext output (not an actual failure):\n%s", err)
	if err == nil {
		t.Fatalf("WaitForSuccessContext expected an error but returned success")
	}

	if !strings.Contains(err.Error(), want) {
		t.Errorf("WaitForSuccessContext err did not contain %q", want)
	}
}

// TestWaitForSuccessContextCutsLongSleep validates that with a long iteration
// interval but short timeout, the function will return based on the shorter
// timeout.
//
// This validates a fix for b/310272841, where WaitForSuccessContext was waiting
// out the entire interval, even though the overall timeout came much sooner.
func TestWaitForSuccessContextCutsLongSleep(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	// wait uses a short overall timeout, but a long iteration interval.
	wait := Waiting{
		Wait:    100 * time.Millisecond,
		Every:   5 * time.Second,
		Timeout: 100 * time.Millisecond,
	}
	f := func(ctx context.Context) error {
		return errors.New("error")
	}
	ch := make(chan error, 1)
	go func() {
		ch <- WaitForSuccessContext(ctx, "WaitForSuccessContext", wait, f)
	}()

	wantReturnWithin := time.Second
	select {
	case <-time.After(wantReturnWithin):
		t.Errorf("Test timed out after %s waiting for WaitForSuccessContext to return based on Waiting.Timeout of %s", wantReturnWithin, wait.Timeout)
	case err := <-ch:
		if err == nil {
			t.Errorf("WaitForSuccessContext error = %v; want non-nil", err)
		}
	}
}

// This test validates that WaitForSuccessContext runs the callback function
// within the interval specified by Waiting.Every, even when the callback takes
// significant time to execute.
func TestWaitForSuccessContextRunsOnConsistentEveryInterval(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	t.Cleanup(cancel)

	wantIterations := 2
	wait := Waiting{
		Every: 400 * time.Millisecond,
		Wait:  500 * time.Millisecond,
	}

	var iterations int
	f := func(ctx context.Context) error {
		iterations++
		<-ctx.Done()
		return errors.New("error")
	}
	err := WaitForSuccessContext(ctx, "WaitForSucess", wait, f)
	if err == nil {
		t.Fatalf("WaitForSuccessContext error = %v; want non-nil", err)
	}

	if iterations != wantIterations {
		t.Errorf("With long running callback, WaitForSuccessContext called func %d times; expected %d iterations", iterations, wantIterations)
	}
}

// This test validates that WaitForSuccessContext properly retries the callback
// when it returns an error indicating that the context is canceled.
//
// This confirms the desired behavior that our retry logic should not abort
// based on test code which uses its own internal context.
func TestWaitForSuccessContextRetriesInternalContextCanceled(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)

	var called int
	f := func(ctx context.Context) error {
		called++
		ctx, cancel := context.WithCancel(ctx)
		cancel()
		<-ctx.Done()
		return ctx.Err()
	}

	err := WaitForSuccessContext(ctx, "WaitForSuccess", testWait, f)
	if err == nil {
		t.Errorf("WaitForSuccessContext err = %v: expected non-nil", err)
	}
	if called < 2 {
		t.Errorf("With internal context canceled, WaitForSuccessContext called func %d times; expected 2 or more retries", called)
	}
}

// This test validates that WaitForSuccessContext properly retries the callback
// when it returns an error indicating that the context has timed out.
//
// This confirms the desired behavior that our retry logic should not abort
// based on test code which uses its own internal context.
func TestWaitForSuccessContextRetriesInternalContextTimeout(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)

	var called int
	f := func(ctx context.Context) error {
		called++
		ctx, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
		defer cancel()
		<-ctx.Done()
		return ctx.Err()
	}

	err := WaitForSuccessContext(ctx, "WaitForSuccess", testWait, f)
	if err == nil {
		t.Errorf("WaitForSuccessContext err = %v: expected non-nil", err)
	}
	if called < 2 {
		t.Errorf("With internal context timeout, WaitForSuccessContext called func %d times; expected 2 or more retries", called)
	}
}

// TestWaitForSuccessContextReturnsMultipleErrors validates that it returns an
// error that includes the last few failures experienced.
func TestWaitForSuccessContextReturnsMultipleErrors(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)

	var count int
	countFunc := func(context.Context) error {
		count++
		return fmt.Errorf("failure %d", count)
	}

	wait := Waiting{
		Wait:    550 * time.Millisecond,
		Every:   100 * time.Millisecond,
		Timeout: 5 * time.Second,
	}
	want := []string{
		"7 errors occurred; retained 6",
		// "failure 1" is overwritten due to buffer capacity.
		"failure 2",      // ~100ms
		"failure 3",      // ~200ms
		"failure 4",      // ~300ms
		"failure 5",      // ~400ms
		"failure 6",      // ~500ms
		"parent context", // ~550ms
	}

	err := WaitForSuccessContext(ctx, "WaitForSuccess", wait, countFunc)
	t.Logf("WaitForSuccessContext output (not an actual failure):\n%s", err)
	if err == nil {
		t.Fatalf("WaitForSuccessContext expected an error but returned success")
	}

	for _, want := range want {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("WaitForSuccessContext err did not contain %q", want)
		}
	}

	if dontWant := "failure 1"; strings.Contains(err.Error(), dontWant) {
		t.Errorf("WaitForSuccessContext contains %q when it should have been overwritten", dontWant)
	}
}

// TestRetryOnErrorContextImmediateSuccessReturnsCorrectCount validates that
// RetryOnErrorContext returns a count of 1 when the function succeeds on the
// first try.
func TestRetryOnErrorContextImmediateSuccessReturnsCorrectCount(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)

	retry := func(err error) bool { return true }
	f := delaySuccessFunc(0, 0)
	count, err := RetryOnErrorContext(ctx, testWait, "RetryOnErrorContext", retry, f)
	if err != nil {
		t.Fatalf("RetryOnErrorContext gave unexpected error: %s", err)
	}

	if count != 1 {
		t.Errorf("RetryOnErrorContext count = %d; want 1", count)
	}
}

func delaySuccessFunc(initialDelay time.Duration, readyDelay time.Duration) func(context.Context) error {
	// Set the ready time based on when the closure executes the first time,
	// rather than when it was defined. This avoids an issue where the function
	// is initialized in a test case definition, but executes much later via
	// t.Parallel.
	var readyTime time.Time
	var once sync.Once
	return func(ctx context.Context) error {
		once.Do(func() {
			readyTime = time.Now().Add(readyDelay)
		})
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(initialDelay):
		}

		if time.Now().Before(readyTime) {
			return errors.New("not ready")
		}
		return nil
	}
}

func immediateSuccessFunc(ctx context.Context) error {
	return nil
}

var testWait = Waiting{
	Wait:    5 * time.Second,
	Every:   1 * time.Second,
	Timeout: 1 * time.Second,
}
