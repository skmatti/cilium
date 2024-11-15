//go:build windows
// +build windows

package metrics

import "syscall"

// Errno2Outcome converts a syscall.Errno to LabelOutcome
func Errno2Outcome(errno syscall.Errno) string {
	if errno != 0 {
		return LabelValueOutcomeFail
	}

	return LabelValueOutcomeSuccess
}
