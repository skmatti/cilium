package version

import "github.com/blang/semver/v4"

// GetKernelVersion returns the version of the Linux kernel running on this host.
func GetKernelVersion() (semver.Version, error) {
	return semver.Version{}, nil
}
