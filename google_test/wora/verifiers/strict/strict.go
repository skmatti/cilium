package strict

import (
	"context"
	"fmt"
	"os"
	"time" // Do not use pkg/time in test code.

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	k8sclient "sigs.k8s.io/controller-runtime/pkg/client"

	klog "gke-internal.googlesource.com/syllogi/sanitized-klog/third_party/klogv2"

	e2escheme "gke-internal.googlesource.com/third_party/cilium/google_test/wora/e2e/pkg/test/scheme"
	"gke-internal.googlesource.com/third_party/cilium/google_test/wora/e2e/pkg/test/utils"
	"gke-internal.googlesource.com/third_party/cilium/google_test/wora/e2e/pkg/test/wait"
)

const (
	testNamespace                 = "strict"
	bootstrapperIP                = "10.200.0.1"
	failJobName                   = "expect-ping-fail"
	passJobName                   = "expect-ping-pass"
	workerNodeLabelSelectorString = "node-role.kubernetes.io/worker"
)

var _ = Describe("Verifiers/Strict", Label("strict"), Ordered, func() {
	var (
		cl        k8sclient.Client
		err       error
		ctx       context.Context
		clientset *kubernetes.Clientset
		jobNode   string
		anetdPod  string
	)

	BeforeAll(func() {
		s := e2escheme.Scheme()

		ctx, _ = context.WithTimeout(context.Background(), 20*time.Minute)

		kubeconfig := os.Getenv("KUBECONFIG")

		config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
		Expect(err).NotTo(HaveOccurred())

		clientset, err = kubernetes.NewForConfig(config)
		Expect(err).NotTo(HaveOccurred(), "Failed to create Kubernetes clientset")

		cl, err = k8sclient.New(config, k8sclient.Options{Scheme: s})
		Expect(err).NotTo(HaveOccurred(), "Failed to create Kubernetes client")
		// Create the test namespace
		err = utils.CreateTestNamespace(ctx, cl, testNamespace)
		Expect(err).NotTo(HaveOccurred(), "Failed to create test namespace")

		// Select one worker node to schedule the test pod.
		nodeList, err := clientset.CoreV1().Nodes().List(ctx, metav1.ListOptions{LabelSelector: workerNodeLabelSelectorString})
		Expect(err).NotTo(HaveOccurred(), "Failed to fetch worker nodes")
		Expect(nodeList.Items).ShouldNot(BeEmpty(), "No worker nodes found")
		jobNode = nodeList.Items[0].Name

		// Fetch the anetd pod running on the same worker node selected above.
		podList, err := clientset.CoreV1().Pods("kube-system").List(ctx, metav1.ListOptions{
			LabelSelector: "k8s-app=cilium",
			FieldSelector: "spec.nodeName=" + jobNode,
		})
		Expect(err).NotTo(HaveOccurred(), fmt.Sprintf("Failed to fetch anetd pod on node %s", jobNode))
		Expect(podList.Items).ShouldNot(BeEmpty(), fmt.Sprintf("No anetd pod found on node %s", jobNode))
		anetdPod = podList.Items[0].Name
	})

	AfterAll(func() {
		klog.Infof("Deleting test namespace %s", testNamespace)
		ns := &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name: testNamespace,
			},
		}
		err = utils.DeleteIfExists(ctx, cl, ns, "namespace")
		Expect(err).NotTo(HaveOccurred())
	})

	It("Verifies pod should not egress without infra-access label", func() {
		// Label "networking.private.gdc.goog/infra-access=enabled" is NOT added to the job.
		jobConfig := fmt.Sprintf(pingFailJobTemplate, testNamespace, bootstrapperIP, jobNode)
		err = utils.KubectlApply(jobConfig)
		Expect(err).NotTo(HaveOccurred(), "Failed to apply Job config")
		defer utils.KubectlDelete(jobConfig)

		startCount, err := GetInfraAccessDeniedDropCount(anetdPod)
		Expect(err).NotTo(HaveOccurred(), "Failed to get start count")
		klog.Infof("start count for 'Infra access denied': %f", startCount)

		job := &batchv1.Job{
			ObjectMeta: metav1.ObjectMeta{
				Name:      failJobName,
				Namespace: testNamespace,
			}}
		err = wait.WaitForSuccessContext(ctx, fmt.Sprintf("Ping job %s complete", failJobName), wait.WaitingMedium, func(ctx context.Context) error {
			if err := cl.Get(ctx, k8sclient.ObjectKeyFromObject(job), job); err != nil {
				return fmt.Errorf("get curl job '%s': %w", failJobName, err)
			}
			return utils.JobComplete(job)
		})
		Expect(err).NotTo(HaveOccurred(), "Ping job validation failed")

		endCount, err := GetInfraAccessDeniedDropCount(anetdPod)
		Expect(err).NotTo(HaveOccurred(), "Failed to get end count")
		klog.Infof("end count for 'Infra access denied': %f", endCount)

		Expect(endCount > startCount).Should(BeTrue(), "Packets are not dropped due to 'Infra access denied'")
	})

	It("Verifies pod should egress traffic with infra-access label", func() {
		// Label "networking.private.gdc.goog/infra-access=enabled" is added to the job.
		jobConfig := fmt.Sprintf(pingPassJobTemplate, testNamespace, bootstrapperIP, jobNode)
		err = utils.KubectlApply(jobConfig)
		Expect(err).NotTo(HaveOccurred(), "Failed to apply Job config")
		defer utils.KubectlDelete(jobConfig)

		job := &batchv1.Job{
			ObjectMeta: metav1.ObjectMeta{
				Name:      passJobName,
				Namespace: testNamespace,
			}}
		err = wait.WaitForSuccessContext(ctx, fmt.Sprintf("Ping job %s complete", passJobName), wait.WaitingMedium, func(ctx context.Context) error {
			if err := cl.Get(ctx, k8sclient.ObjectKeyFromObject(job), job); err != nil {
				return fmt.Errorf("get curl job '%s': %w", passJobName, err)
			}
			return utils.JobComplete(job)
		})
		Expect(err).NotTo(HaveOccurred(), "Ping job validation failed")
	})
})
