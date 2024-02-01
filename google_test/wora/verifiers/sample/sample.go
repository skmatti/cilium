package sample

import (
	"context"
	"os"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"gke-internal.googlesource.com/anthos-networking/test-infra/pkg/client"
)

var _ = Describe("Verifiers/Sample", Label("sample"), func() {
	var c client.Interface
	var err error

	BeforeEach(func() {
		kubeconfig := os.Getenv("KUBECONFIG")
		c, err = client.NewClientSet(kubeconfig)
		Expect(err).NotTo(HaveOccurred())
	})

	It("can list nodes", func() {
		nodes, err := c.CoreV1().Nodes().List(context.Background(), metav1.ListOptions{})
		Expect(err).NotTo(HaveOccurred())
		Expect(nodes.Items).NotTo(HaveLen(0))
	})
})
