package errorring

import (
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/go-multierror"
)

// Used for unit testing.
var nowFunc = time.Now

// ErrorRing is a ring buffer which holds multiple errors, up to its max
// capacity. Once the capacity is reached, adding a new error will overwrite the
// oldest error in the buffer.
type ErrorRing struct {
	errs  []error
	count int
}

// New creates an ErrorRing with the given size.
func New(size int) (*ErrorRing, error) {
	if size <= 0 {
		return nil, fmt.Errorf("create new ErrorRing with size %d: must be > 0", size)
	}
	return &ErrorRing{
		errs: make([]error, size),
	}, nil
}

// Add an error to the ErrorRing, with timestamp.
// - If the err is nil, no change is made.
// - If capacity is full, the oldest error will be overwritten.
func (r *ErrorRing) Add(err error) {
	if err == nil {
		return
	}
	size := len(r.errs)
	next := r.count % size
	r.count++
	ts := nowFunc().Format("15:04:05.000000")
	err = fmt.Errorf("%s: error %d: %w", ts, r.count, err)
	r.errs[next] = err
}

// Count returns a count of the errors that have been added to the ErrorRing,
// including those that have been overwritten.
func (r *ErrorRing) Count() int {
	return r.count
}

// Last returns the last error. If no errors have been added, it will be nil.
func (r *ErrorRing) Last() error {
	size := len(r.errs)
	last := (r.count + size - 1) % size
	return r.errs[last]
}

// Complete returns a multierror with the contents of the ErrorRing. Errors are
// ordered from oldest to most recent.
func (r *ErrorRing) Complete() error {
	var multiErr *multierror.Error
	size := len(r.errs)
	for i := r.count; i < r.count+size; i++ {
		e := r.errs[i%size]
		if e != nil {
			multiErr = multierror.Append(multiErr, e)
		}
	}
	if multiErr != nil {
		multiErr.ErrorFormat = r.errorFormat
		return multiErr
	}
	return nil
}

// errorFormat implements ErrorFormat for multierror.Error.
func (r *ErrorRing) errorFormat(err []error) string {
	var out strings.Builder
	if len(err) == 1 {
		out.WriteString(fmt.Sprintf("%d error occurred", r.count))
	} else {
		out.WriteString(fmt.Sprintf("%d errors occurred", r.count))
	}
	out.WriteString(fmt.Sprintf("; retained %d in order from oldest to most recent:\n", len(err)))
	for _, e := range err {
		out.WriteString(fmt.Sprintf("\t* %s\n", e))
	}
	return out.String()
}
