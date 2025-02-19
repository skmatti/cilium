package hostfirewall

import (
	"context"
	"os"
	"time" // Do not use pkg/time in test code.

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/klog/v2"
	k8sclient "sigs.k8s.io/controller-runtime/pkg/client"

	e2escheme "gke-internal.googlesource.com/third_party/cilium/google_test/wora/e2e/pkg/test/scheme"
	"gke-internal.googlesource.com/third_party/cilium/google_test/wora/e2e/pkg/test/utils"
)

const (
	testLabelKey                    = "testPod"
	testLabelValue1                 = "label1"
	testLabelValue2                 = "label2"
	CCNPonWorkerNode1               = "ccnp-on-worker1"
	pod0onWorker0                   = "pod0-on-worker0"
	pod1onWorker0                   = "pod1-on-worker0"
	pod0onControlPlane0             = "pod0-on-controlplane0"
	pod1onControlPlane0             = "pod1-on-controlplane0"
	hostNetworkPodOnWorker1         = "worker1-hostnetwork-pod"
	testNamespace1                  = "hostfirewall-ns-1"
	testNamespace2                  = "hostfirewall-ns-2"
	curlTimeoutSeconds              = 10
	requiredNumberOfWorkerNodeIPs   = 2
	requiredNumberOfControlPlaneIPs = 1
	workerNodeLabel                 = "node-role.kubernetes.io/worker="
	controlPlaneNodeLabel           = "node-role.kubernetes.io/control-plane="
)

var _ = Describe("Verifiers/hostfirewall", Label("hostfirewall"), Ordered, func() {
	var (
		cl             k8sclient.Client
		err            error
		config         *rest.Config
		ctx            context.Context
		controlplaneip string
		worker0ip      string
		worker1ip      string
	)

	BeforeAll(func() {
		ctx, _ = context.WithTimeout(context.Background(), 20*time.Minute)
		kubeconfig := os.Getenv("KUBECONFIG")
		Expect(kubeconfig).ToNot(BeEmpty())
		Expect(kubeconfig).To(BeAnExistingFile(), "kubeconfig file should exist")

		config, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
		Expect(err).NotTo(HaveOccurred())

		s := e2escheme.Scheme()

		cl, err = k8sclient.New(config, k8sclient.Options{Scheme: s})
		Expect(err).NotTo(HaveOccurred())

		// Create the test namespaces
		err = utils.CreateTestNamespace(ctx, cl, testNamespace1)
		Expect(err).NotTo(HaveOccurred(), "Failed to create test namespace 1")
		err = utils.CreateTestNamespace(ctx, cl, testNamespace2)
		Expect(err).NotTo(HaveOccurred(), "Failed to create test namespace 2")

		controlplaneNodeIPs, err := utils.GetRequiredNumberOfNodeIPsByLabel(ctx, cl, controlPlaneNodeLabel, requiredNumberOfControlPlaneIPs)
		Expect(err).NotTo(HaveOccurred())

		controlplaneip = controlplaneNodeIPs[0]
		klog.Info("controlplane0 ip is ", controlplaneip)

		workerNodeIPs, err := utils.GetRequiredNumberOfNodeIPsByLabel(ctx, cl, workerNodeLabel, requiredNumberOfWorkerNodeIPs)
		Expect(err).NotTo(HaveOccurred())

		worker0ip = workerNodeIPs[0]
		klog.Info("worker0 ip is ", worker0ip)

		worker1ip = workerNodeIPs[1]
		klog.Info("worker1 ip is ", worker1ip)

		// Creating a host network pod for worker node 1
		_, err = utils.CreatePod(ctx, cl, hostNetworkPodOnWorker1, testNamespace1, utils.WithNodeSelector(worker1ip), utils.WithHostNetworking(), utils.WithResponderContainer())
		Expect(err).ToNot(HaveOccurred())

		// Creating a CCNP policy for worker node 1
		err = applyCCNPWithIngressPolicy(cl, CCNPonWorkerNode1, worker1ip, testLabelKey, testLabelValue1)
		Expect(err).ToNot(HaveOccurred(), "Failed to apply the CCNP")
		klog.Infof("Applied CCNP which allows ingress from pods with label testPod=label1 to worker1 node")
	})

	Describe("Pod to Node Connectivity tests when CCNP allows ingress", func() {

		// pod0-on-worker0 is on worker0 node and on hostfirewall-ns-1 namespace with label testPod=label1
		// pod0-on-controlplane0 is on controlplane0 node and on hostfirewall-ns-1 namespace with label testPod=label1
		// CCNP should allow both pod0-on-worker0 and pod0-on-controlplane0
		It("Validates connectivity when CCNP allows ingress from pods on same namespace but on different nodes", func() {
			_, err = utils.CreatePod(ctx, cl, pod0onWorker0, testNamespace1, utils.WithNodeSelector(worker0ip), utils.WithLabel(testLabelKey, testLabelValue1))
			Expect(err).ToNot(HaveOccurred())

			_, err = utils.CreatePod(ctx, cl, pod0onControlPlane0, testNamespace1, utils.WithNodeSelector(controlplaneip), utils.WithLabel(testLabelKey, testLabelValue1))
			Expect(err).ToNot(HaveOccurred())

			// pod0-on-worker0 is on worker0 node and on hostfirewall-ns-1 namespace with label testPod=label1
			// pod0-on-controlplane0 is on controlplane0 node and on hostfirewall-ns-1 namespace with label testPod=label1
			err = utils.RunCurlFromPodWithTimeoutLimit(ctx, cl, pod0onWorker0, hostNetworkPodOnWorker1, worker1ip, utils.ResponderPort, testNamespace1, curlTimeoutSeconds)
			Expect(err).ToNot(HaveOccurred())
			err = utils.RunCurlFromPodWithTimeoutLimit(ctx, cl, pod0onControlPlane0, hostNetworkPodOnWorker1, worker1ip, utils.ResponderPort, testNamespace1, curlTimeoutSeconds)
			Expect(err).ToNot(HaveOccurred())

			err = deleteAndWaitForPodDeletion(ctx, cl, pod0onControlPlane0, testNamespace1)
			Expect(err).ToNot(HaveOccurred(), "Failed to delete the pod")

			err = deleteAndWaitForPodDeletion(ctx, cl, pod0onWorker0, testNamespace1)
			Expect(err).ToNot(HaveOccurred(), "Failed to delete the pod")

		})

		// pod1-on-worker0 is on worker0 node and on hostfirewall-ns-1 namespace with label testPod=label1
		// pod1-on-controlplane0 is on controlplane0 node and on hostfirewall-ns-2 namespace with label testPod=label1
		// CCNP should allow both pod1-on-worker0 and pod1-on-controlplane0
		It("Validates connectivity when CCNP allows from pods on different namespace and on different nodes", func() {
			_, err = utils.CreatePod(ctx, cl, pod1onWorker0, testNamespace1, utils.WithNodeSelector(worker0ip), utils.WithLabel(testLabelKey, testLabelValue1))
			Expect(err).ToNot(HaveOccurred())

			_, err = utils.CreatePod(ctx, cl, pod1onControlPlane0, testNamespace2, utils.WithNodeSelector(controlplaneip), utils.WithLabel(testLabelKey, testLabelValue1))
			Expect(err).ToNot(HaveOccurred())

			err = utils.RunCurlFromPodWithTimeoutLimit(ctx, cl, pod1onWorker0, hostNetworkPodOnWorker1, worker1ip, utils.ResponderPort, testNamespace1, curlTimeoutSeconds)
			Expect(err).ToNot(HaveOccurred())
			err = utils.RunCurlFromPodWithTimeoutLimit(ctx, cl, pod1onControlPlane0, hostNetworkPodOnWorker1, worker1ip, utils.ResponderPort, testNamespace2, curlTimeoutSeconds)
			Expect(err).ToNot(HaveOccurred())

			err = deleteAndWaitForPodDeletion(ctx, cl, pod1onControlPlane0, testNamespace2)
			Expect(err).ToNot(HaveOccurred(), "Failed to delete the pod")

			err = deleteAndWaitForPodDeletion(ctx, cl, pod1onWorker0, testNamespace1)
			Expect(err).ToNot(HaveOccurred(), "Failed to delete the pod")
		})
	})

	Describe("Pod to Node Connectivity tests when CCNP denies ingress", func() {

		// pod0-on-worker0 is on worker0 node and on hostfirewall-ns-1 namespace with label testPod=label2
		// pod0-on-controlplane0 is on controlplane0 node and on hostfirewall-ns-1 namespace with label testPod=label2
		// CCNP should deny both pod0-on-worker0 and pod0-on-controlplane0
		It("Validates connectivity when CCNP denies ingress from pods on same namespace but on different nodes", func() {

			_, err = utils.CreatePod(ctx, cl, pod0onWorker0, testNamespace1, utils.WithNodeSelector(worker0ip), utils.WithLabel(testLabelKey, testLabelValue2))
			Expect(err).ToNot(HaveOccurred())

			_, err = utils.CreatePod(ctx, cl, pod0onControlPlane0, testNamespace1, utils.WithNodeSelector(controlplaneip), utils.WithLabel(testLabelKey, testLabelValue2))
			Expect(err).ToNot(HaveOccurred())

			// pod0-on-worker0 is on worker0 node and on hostfirewall-ns-1 namespace with label testPod=label2
			// pod0-on-controlplane0 is on controlplane0 node and on hostfirewall-ns-1 namespace with label testPod=label2
			err = utils.RunCurlFromPodWithTimeoutLimit(ctx, cl, pod0onWorker0, hostNetworkPodOnWorker1, worker1ip, utils.ResponderPort, testNamespace1, curlTimeoutSeconds)
			Expect(err).To(HaveOccurred())
			err = utils.RunCurlFromPodWithTimeoutLimit(ctx, cl, pod0onControlPlane0, hostNetworkPodOnWorker1, worker1ip, utils.ResponderPort, testNamespace1, curlTimeoutSeconds)
			Expect(err).To(HaveOccurred())

			err = deleteAndWaitForPodDeletion(ctx, cl, pod0onControlPlane0, testNamespace1)
			Expect(err).ToNot(HaveOccurred(), "Failed to delete the pod")

			err = deleteAndWaitForPodDeletion(ctx, cl, pod0onWorker0, testNamespace1)
			Expect(err).ToNot(HaveOccurred(), "Failed to delete the pod")
		})

		// pod1-on-worker0 is on worker0 node and on hostfirewall-ns-1 namespace with label testPod=label2
		// pod1-on-controlplane0 is on controlplane0 node and on hostfirewall-ns-2 namespace with label testPod=label2
		// CCNP should deny both pod1-on-worker0 and pod1-on-controlplane0
		It("Validates connectivity when CCNP denies from pods on different namespace and on different nodes", func() {

			_, err = utils.CreatePod(ctx, cl, pod1onWorker0, testNamespace1, utils.WithNodeSelector(worker0ip), utils.WithLabel(testLabelKey, testLabelValue2))
			Expect(err).ToNot(HaveOccurred())

			_, err = utils.CreatePod(ctx, cl, pod1onControlPlane0, testNamespace2, utils.WithNodeSelector(controlplaneip), utils.WithLabel(testLabelKey, testLabelValue2))
			Expect(err).ToNot(HaveOccurred())

			err = utils.RunCurlFromPodWithTimeoutLimit(ctx, cl, pod1onWorker0, hostNetworkPodOnWorker1, worker1ip, utils.ResponderPort, testNamespace1, curlTimeoutSeconds)
			Expect(err).To(HaveOccurred())
			err = utils.RunCurlFromPodWithTimeoutLimit(ctx, cl, pod1onControlPlane0, hostNetworkPodOnWorker1, worker1ip, utils.ResponderPort, testNamespace2, curlTimeoutSeconds)
			Expect(err).To(HaveOccurred())

			err = deleteAndWaitForPodDeletion(ctx, cl, pod1onControlPlane0, testNamespace2)
			Expect(err).ToNot(HaveOccurred(), "Failed to delete the pod")

			err = deleteAndWaitForPodDeletion(ctx, cl, pod1onWorker0, testNamespace1)
			Expect(err).ToNot(HaveOccurred(), "Failed to delete the pod")
		})
	})
	AfterAll(func() {
		deleteCCNP(cl, config, CCNPonWorkerNode1)
		deleteAndWaitForPodDeletion(ctx, cl, hostNetworkPodOnWorker1, testNamespace1)

		klog.Infof("Deleting test namespace %s", testNamespace1)
		ns := &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name: testNamespace1,
			},
		}
		err = utils.DeleteIfExists(ctx, cl, ns, "namespace")
		Expect(err).NotTo(HaveOccurred())

		klog.Infof("Deleting test namespace %s", testNamespace2)
		ns = &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name: testNamespace2,
			},
		}
		err = utils.DeleteIfExists(ctx, cl, ns, "namespace")
		Expect(err).NotTo(HaveOccurred())
	})
})
