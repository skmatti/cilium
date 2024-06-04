package sample

import (
	"context"
	"fmt"
	"os"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	klog "gke-internal.googlesource.com/syllogi/sanitized-klog"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"gke-internal.googlesource.com/anthos-networking/test-infra/pkg/client"
)

const (
	anetdLabelSelectorLabel        = "k8s-app=cilium"
	anetOperatorLabelSelectorLabel = "io.cilium/app=operator"
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

	Describe("StatusOfCilium", func() {
		var anetdPods *corev1.PodList
		var anetOperatorPods *corev1.PodList

		BeforeEach(func() {
			anetdPods, err = c.CoreV1().Pods("kube-system").List(context.Background(), metav1.ListOptions{LabelSelector: anetdLabelSelectorLabel})
			Expect(err).NotTo(HaveOccurred())
			anetOperatorPods, err = c.CoreV1().Pods("kube-system").List(context.Background(), metav1.ListOptions{LabelSelector: anetOperatorLabelSelectorLabel})
			Expect(err).NotTo(HaveOccurred())
		})
		It("All anetd pods are running", func() {
			for _, anetdPod := range anetdPods.Items {
				Expect(anetdPod.Status.Phase).To(Equal(corev1.PodRunning), fmt.Sprintf("Pod name: %s on node: %s has phase %s", anetdPod.Name, anetdPod.Spec.NodeName, anetdPod.Status.Phase))
				for _, container := range anetdPod.Spec.Containers {
					if container.Name == "cilium-agent" {
						klog.Infof("Pod: %s's container: %s has image: %s.", anetdPod.Name, container.Name, container.Image)
						break
					}
				}
			}
		})
		It("All anet-operator pods are running", func() {
			for _, anetOperatorPod := range anetOperatorPods.Items {
				Expect(anetOperatorPod.Status.Phase).To(Equal(corev1.PodRunning), fmt.Sprintf("Pod name: %s on node: %s has phase %s", anetOperatorPod.Name, anetOperatorPod.Spec.NodeName, anetOperatorPod.Status.Phase))
				for _, container := range anetOperatorPod.Spec.Containers {
					if container.Name == "cilium-operator" {
						klog.Infof("Pod: %s's container: %s has image: %s.", anetOperatorPod.Name, container.Name, container.Image)
						break
					}
				}
			}
		})
		It("All anetd pods are ready", func() {
			for _, anetdPod := range anetdPods.Items {
				for _, condition := range anetdPod.Status.Conditions {
					if condition.Type == corev1.PodReady {
						Expect(condition.Status == corev1.ConditionTrue).To(BeTrue(), fmt.Sprintf("Pod: %s has %s status: %s", anetdPod.Name, condition.Type, condition.Status))
						break
					}
				}
			}
		})

		It("All anet-operator pods are ready", func() {
			for _, anetOperatorPod := range anetOperatorPods.Items {
				for _, condition := range anetOperatorPod.Status.Conditions {
					if condition.Type == corev1.PodReady {
						Expect(condition.Status == corev1.ConditionTrue).To(BeTrue(), fmt.Sprintf("Pod: %s has %s status: %s", anetOperatorPod.Name, condition.Type, condition.Status))
						break
					}
				}
			}
		})
	})
})
