package hostfirewall

import (
	"context"
	"fmt"
	"os"
	"time" // Do not use pkg/time in test code.

	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/rand"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"sigs.k8s.io/controller-runtime/pkg/client"
	k8sclient "sigs.k8s.io/controller-runtime/pkg/client"

	klog "gke-internal.googlesource.com/syllogi/sanitized-klog/third_party/klogv2"
	e2escheme "gke-internal.googlesource.com/third_party/cilium/google_test/wora/e2e/pkg/test/scheme"
	"gke-internal.googlesource.com/third_party/cilium/google_test/wora/e2e/pkg/test/utils"
)

const (
	testLabelKey          = "test-pod"
	testLabelValueAllow   = "allow"
	testLabelValueDeny    = "deny"
	testCCNPName          = "allow-traffic-from-test-pod"
	testNamespace1        = "hostfirewall-ns-1"
	testNamespace2        = "hostfirewall-ns-2"
	maxNodeNameLen        = 10
	requiredWorkerNodes   = 2
	requiredCPNodes       = 1
	workerNodeLabel       = "node-role.kubernetes.io/worker"
	controlPlaneNodeLabel = "node-role.kubernetes.io/control-plane"
)

var _ = Describe("Verifiers/hostfirewall", Label("hostfirewall"), Ordered, func() {
	var (
		cl          k8sclient.Client
		err         error
		config      *rest.Config
		ctx         context.Context
		cpNode      utils.Node
		workerNodes []utils.Node
	)

	BeforeAll(func() {
		ctx, _ = context.WithTimeout(context.Background(), 20*time.Minute)
		kubeconfig := os.Getenv("KUBECONFIG")
		Expect(kubeconfig).ToNot(BeEmpty(), "KUBECONFIG env var must be set")
		Expect(kubeconfig).To(BeAnExistingFile(), "kubeconfig file should exist")

		config, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
		Expect(err).NotTo(HaveOccurred())

		cl, err = k8sclient.New(config, k8sclient.Options{Scheme: e2escheme.Scheme()})
		Expect(err).NotTo(HaveOccurred())

		// Create the test namespaces
		err = utils.CreateTestNamespace(ctx, cl, testNamespace1)
		Expect(err).NotTo(HaveOccurred())
		err = utils.CreateTestNamespace(ctx, cl, testNamespace2)
		Expect(err).NotTo(HaveOccurred())

		cpNodes, err := utils.GetRequiredNumberOfNodesByLabel(ctx, cl, controlPlaneNodeLabel, requiredCPNodes)
		Expect(err).NotTo(HaveOccurred())
		cpNode = cpNodes[0]

		workerNodes, err = utils.GetRequiredNumberOfNodesByLabel(ctx, cl, workerNodeLabel, requiredWorkerNodes)
		Expect(err).NotTo(HaveOccurred())

		// Creating a host network pod for worker node 1
		hostNetworkServerPod := fmt.Sprintf("server-on-%s-%s", workerNodes[1].Name[:maxNodeNameLen], rand.String(5))
		_, err = utils.CreatePod(ctx, cl, hostNetworkServerPod, testNamespace1, utils.WithNodeSelector(workerNodes[1].IP), utils.WithHostNetworking(), utils.WithResponderContainer())
		Expect(err).ToNot(HaveOccurred())

		// Creating a CCNP policy for worker node 1
		err = applyIngressCCNP(cl, testCCNPName, workerNodes[1].IP, testLabelKey, testLabelValueAllow)
		Expect(err).ToNot(HaveOccurred(), "Failed to apply the CCNP")
		klog.Infof("Applied CCNP which allows ingress from pods with label %s=%s to %s node", testLabelKey, testLabelValueAllow, workerNodes[1].Name)
	})

	// testPodToNodeConnectivity creates two pods with a given label, verifies connectivity to a target IP,
	// and cleans up the pods.
	testPodToNodeConnectivity := func(pod1NS, pod2NS, labelValue string, shouldSucceed bool) {
		// Using unique names to avoid conflicts if tests were to run in parallel in the future.
		// And it makes debugging easier.
		randSuffix := rand.String(5)
		podOnWorkerName := fmt.Sprintf("client-on-%s-%s", workerNodes[0].Name[:maxNodeNameLen], randSuffix)
		podOnControlPlaneName := fmt.Sprintf("client-on-%s-%s", cpNode.Name[:maxNodeNameLen], randSuffix)

		// Create pod on worker node
		_, err := utils.CreatePod(ctx, cl, podOnWorkerName, pod1NS, utils.WithNodeSelector(workerNodes[0].IP), utils.WithLabel(testLabelKey, labelValue))
		Expect(err).ToNot(HaveOccurred())

		// Create pod on control-plane node
		_, err = utils.CreatePod(ctx, cl, podOnControlPlaneName, pod2NS, utils.WithNodeSelector(cpNode.IP), utils.WithLabel(testLabelKey, labelValue))
		Expect(err).ToNot(HaveOccurred())

		// Verify connectivity
		err = utils.VerifyCurlFromPod(ctx, pod1NS, podOnWorkerName, workerNodes[1].IP, utils.ResponderPort, shouldSucceed, "")
		Expect(err).ToNot(HaveOccurred())

		err = utils.VerifyCurlFromPod(ctx, pod2NS, podOnControlPlaneName, workerNodes[1].IP, utils.ResponderPort, shouldSucceed, "")
		Expect(err).ToNot(HaveOccurred())
	}

	Describe("Pod to Node Connectivity when CCNP allow ingress", func() {
		It("from pod in same namespace but on different node", func() {
			testPodToNodeConnectivity(testNamespace1, testNamespace1, testLabelValueAllow, true)
		})

		It("from pod in different namespace and on different node", func() {
			testPodToNodeConnectivity(testNamespace1, testNamespace2, testLabelValueAllow, true)
		})
	})

	Describe("Pod to Node Connectivity when CCNP denies ingress", func() {
		It("from pod in same namespace but on different node", func() {
			testPodToNodeConnectivity(testNamespace1, testNamespace1, testLabelValueDeny, false)
		})

		It("from pod in different namespace and on different node", func() {
			testPodToNodeConnectivity(testNamespace1, testNamespace2, testLabelValueDeny, false)
		})
	})
	AfterAll(func() {
		if cl == nil {
			return
		}
		objs := []client.Object{
			&ciliumv2.CiliumClusterwideNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: testCCNPName,
				},
			},
			&corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: testNamespace1,
				},
			},
			&corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: testNamespace2,
				},
			},
		}
		for _, obj := range objs {
			Expect(utils.DeleteIfExists(ctx, cl, obj)).NotTo(HaveOccurred())
		}
		for _, obj := range objs {
			Expect(utils.WaitForDeletion(ctx, cl, obj)).NotTo(HaveOccurred())
		}
	})
})
