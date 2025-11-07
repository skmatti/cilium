package e2e

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	_ "gke-internal.googlesource.com/third_party/cilium/google_test/wora/e2e/verifiers/1n-smoke"
	_ "gke-internal.googlesource.com/third_party/cilium/google_test/wora/e2e/verifiers/bpfprog"
	_ "gke-internal.googlesource.com/third_party/cilium/google_test/wora/e2e/verifiers/connectivity"
	_ "gke-internal.googlesource.com/third_party/cilium/google_test/wora/e2e/verifiers/egressnat"
	_ "gke-internal.googlesource.com/third_party/cilium/google_test/wora/e2e/verifiers/externallb"
	_ "gke-internal.googlesource.com/third_party/cilium/google_test/wora/e2e/verifiers/geneve"
	_ "gke-internal.googlesource.com/third_party/cilium/google_test/wora/e2e/verifiers/hostfirewall"
	_ "gke-internal.googlesource.com/third_party/cilium/google_test/wora/e2e/verifiers/internallb"
	_ "gke-internal.googlesource.com/third_party/cilium/google_test/wora/e2e/verifiers/kubevirt"
	_ "gke-internal.googlesource.com/third_party/cilium/google_test/wora/e2e/verifiers/l3multinetwork"
	_ "gke-internal.googlesource.com/third_party/cilium/google_test/wora/e2e/verifiers/l3vm"
	_ "gke-internal.googlesource.com/third_party/cilium/google_test/wora/e2e/verifiers/loadbalancer"
	_ "gke-internal.googlesource.com/third_party/cilium/google_test/wora/e2e/verifiers/multicluster"
	_ "gke-internal.googlesource.com/third_party/cilium/google_test/wora/e2e/verifiers/multinetwork"
	_ "gke-internal.googlesource.com/third_party/cilium/google_test/wora/e2e/verifiers/multinic_hostfirewall"
	_ "gke-internal.googlesource.com/third_party/cilium/google_test/wora/e2e/verifiers/sample"
	_ "gke-internal.googlesource.com/third_party/cilium/google_test/wora/e2e/verifiers/strict"
	_ "gke-internal.googlesource.com/third_party/cilium/google_test/wora/e2e/verifiers/tailcall"
)

func TestE2E(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "E2ETest Suite")
}
