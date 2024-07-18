package errorring

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// TestErrorRing validates the output of some basic test cases adding various
// numbers of errors to the ErrorRing.
func TestErrorRing(t *testing.T) {
	tcs := []struct {
		name         string
		numErrors    int
		linesContain []string
	}{
		{
			name:      "one error",
			numErrors: 1,
			linesContain: []string{
				"1 error occurred; retained 1",
				"error 1: failed",
			},
		},
		{
			name:      "three errors",
			numErrors: 3,
			linesContain: []string{
				"3 errors occurred; retained 3",
				"error 1: failed",
				"error 2: failed",
				"error 3: failed",
			},
		},
		{
			name:      "five errors",
			numErrors: 5,
			linesContain: []string{
				"5 errors occurred; retained 5",
				"error 1: failed",
				"error 2: failed",
				"error 3: failed",
				"error 4: failed",
				"error 5: failed",
			},
		},
		{
			name:      "seven errors",
			numErrors: 7,
			linesContain: []string{
				"7 errors occurred; retained 5",
				"error 3: failed",
				"error 4: failed",
				"error 5: failed",
				"error 6: failed",
				"error 7: failed",
			},
		},
		{
			name:      "ten errors",
			numErrors: 10,
			linesContain: []string{
				"10 errors occurred; retained 5",
				"error 6: failed",
				"error 7: failed",
				"error 8: failed",
				"error 9: failed",
				"error 10: failed",
			},
		},
		{
			name:      "twelve errors",
			numErrors: 12,
			linesContain: []string{
				"12 errors occurred; retained 5",
				"error 8: failed",
				"error 9: failed",
				"error 10: failed",
				"error 11: failed",
				"error 12: failed",
			},
		},
	}

	for _, tc := range tcs {
		tc := tc // Capture for t.Parallel.
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			errs := newTestErrorRing(t)
			for i := 0; i < tc.numErrors; i++ {
				errs.Add(errors.New("failed"))
			}
			err := errs.Complete()
			if err == nil {
				t.Fatalf("ErrorRing.Complete() returned no error; expected an error")
			}
			t.Logf("ErrorRing output (not an actual failure):\n%s", err)

			if got, want := errs.Count(), tc.numErrors; got != want {
				t.Errorf("ErrorRing.Count() = %d; want %d", got, want)
			}

			s := strings.TrimSpace(err.Error())
			lines := strings.Split(s, "\n")
			if got, want := len(lines), len(tc.linesContain); got != want {
				t.Fatalf("ErrorRing returned error with %d lines, expected %d", got, want)
			}
			for i := range lines {
				if got, want := lines[i], tc.linesContain[i]; !strings.Contains(got, want) {
					t.Errorf("Line %d = %q; want contains %q", i, got, want)
				}
			}
		})
	}
}

// TestErrorRingErrors validates error conditions for ErrorRing.
func TestErrorRingErrors(t *testing.T) {
	if _, err := New(0); err == nil {
		t.Fatalf("Create ErrorRing with size 0 succeeded; expected error")
	}
}

// TestErrorRingEmpty validates that an empty ErrorRing returns a nil error.
func TestErrorRingEmpty(t *testing.T) {
	t.Parallel()

	errs := newTestErrorRing(t)
	err := errs.Complete()
	t.Logf("ErrorRing output (not an actual failure):\n%s", err)

	if err != nil {
		t.Errorf("Empty ErrRing should be nil")
	}
	if got, want := errs.Count(), 0; got != want {
		t.Errorf("ErrorRing.Count() = %d; want %d", got, want)
	}
}

// TestErrorRingAddNilError validates that adding a nil error to an ErrorRing
// does not change its state.
func TestErrorRingAddNilError(t *testing.T) {
	t.Parallel()

	errs := newTestErrorRing(t)
	var nilErr error
	errs.Add(nilErr)
	err := errs.Complete()
	t.Logf("ErrorRing output (not an actual failure):\n%s", err)

	if err != nil {
		t.Error("After adding nil error, ErrRing should still be nil")
	}
	if got, want := errs.Count(), 0; got != want {
		t.Errorf("ErrorRing.Count() = %d; want %d", got, want)
	}
}

// TestErrorRingHasTimestamp validates that the output contains a timestamp for
// when each error was added.
func TestErrorRingHasTimestamp(t *testing.T) {
	// Don't execute this test in parallel since it replaces the nowFunc.
	oldNow := nowFunc
	t.Cleanup(func() {
		nowFunc = oldNow
	})
	nowFunc = func() time.Time {
		return time.Date(1985, time.October, 26, 1, 20, 5, 123456789, time.UTC)
	}

	errs := newTestErrorRing(t)
	errs.Add(errors.New("oh no"))
	err := errs.Complete()
	if err == nil {
		t.Fatalf("ErrorRing.Complete() returned no error; expected an error")
	}
	t.Logf("ErrorRing output (not an actual failure):\n%s", err)

	want := "01:20:05.123456"
	if !strings.Contains(err.Error(), want) {
		t.Errorf("ErrorRing does not contain %q", want)
	}
}

// TestErrorRingLast validates standard cases for ErrorRing.Last().
func TestErrorRingLast(t *testing.T) {
	errs, err := New(2)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("Created ErrorRing of size 2")

	if got := errs.Last(); got != nil {
		t.Errorf("Before any errors are added; errs.Last() = %v; should be nil", got)
	}

	for _, e := range []string{"one", "two", "three"} {
		err := errors.New(e)
		errs.Add(err)
		t.Logf("Added error %s", err)

		if got := errs.Last(); !errors.Is(got, err) {
			t.Errorf("After adding %s error; errs.Last() = %v; want %v", e, got, err)
		}
	}
}

// TestErrorRingCompleteWrapsErrors validates that .Complete() returns wrapped
// errors which can unwrap individual errors with errors.Is.
func TestErrorRingCompleteWrapsErrors(t *testing.T) {
	errs, err := New(2)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("Created ErrorRing of size 2")

	for _, e := range []string{"one", "two", "three"} {
		err := errors.New(e)
		errs.Add(err)
		t.Logf("Added error %s", err)

		if got := errs.Complete(); !errors.Is(got, err) {
			t.Errorf("After adding %s error; errs.Complete() = %v; want contains %v", e, got, err)
		}
	}
}

func newTestErrorRing(t *testing.T) *ErrorRing {
	t.Helper()
	ring, err := New(5)
	if err != nil {
		t.Fatal(err)
	}
	return ring
}
