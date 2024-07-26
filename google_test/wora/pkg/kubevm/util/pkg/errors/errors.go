package errors

import (
	"regexp"
)

// HasNoMatchError determines if the err contains no match for a specific kind error
// Here to use the regex match instead of type match, because the return error is a combination
// of 2 errors, which makes extract a specific error type impossible
// The original error type match should be IsNoMatchError
// https://source.corp.google.com/cloud-gke/syllogi-baremetal/third_party/cluster-api/vendor/k8s.io/apimachinery/pkg/api/meta/errors.go;l=111?q=IsNoMatchError&ss=piper%2FGoogle%2Fcloud-gke:syllogi-baremetal%2F
// Example for matcher 1: "unable to recognize tmp/kout....., no matches for kind VirtualMachine in version kubevirt.io/v1"
// Example for matcher 1: "no matches for kind VirtualMachine in version kubevirt.io/v1".
// Example for matcher 2: "the server could not find the requested resource (get virtualmachines.kubevirt.io)".
func HasNoMatchError(err error) bool {
	errorMatcher1 := regexp.MustCompile(`no matches for kind .*? in version .*?`)
	errorMatcher2 := regexp.MustCompile(`could not find the requested resource.*?`)
	return errorMatcher1.MatchString(err.Error()) || errorMatcher2.MatchString(err.Error())
}
