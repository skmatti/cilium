package e2e

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	_ "gke-internal.googlesource.com/third_party/cilium/google_test/wora/e2e/verifiers/sample"
)

func TestE2E(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "E2ETest Suite")
}
