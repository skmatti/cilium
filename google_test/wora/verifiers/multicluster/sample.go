package multicluster

import (
	"context"
	"os"
	"time" // Do not use pkg/time in test code.

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"gke-internal.googlesource.com/anthos-networking/test-infra/pkg/artifact"
	klog "gke-internal.googlesource.com/syllogi/sanitized-klog/third_party/klogv2"
)

var _ = Describe("Sample MultiCluster", Label("sample-multicluster"), Ordered, func() {
	var (
		ctx        context.Context
		clusters   artifact.ClusterInfoList
		clientsets []*kubernetes.Clientset
	)

	BeforeAll(func() {
		ctx, _ = context.WithTimeout(context.Background(), 10*time.Minute)

		artifacts, ok := os.LookupEnv("ARTIFACTS")
		Expect(ok).To(BeTrue())
		Expect(artifacts).NotTo(BeEmpty())

		var err error
		clusters, err = artifact.NewClusterInfoList(artifacts)
		Expect(err).NotTo(HaveOccurred())
		Expect(clusters).NotTo(BeEmpty())

		clientsets, err = clusters.NewClientsets()
		Expect(err).NotTo(HaveOccurred())
		Expect(clientsets).NotTo(BeEmpty())
	})

	It("can list nodes on all clusters", func() {
		for idx, clientset := range clientsets {
			nodes, err := clientset.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
			Expect(err).NotTo(HaveOccurred())
			klog.Infof("Found %d nodes on (%s).", len(nodes.Items), clusters[idx].ClusterName)
			Expect(nodes.Items).NotTo(HaveLen(0))
		}
	})
})
