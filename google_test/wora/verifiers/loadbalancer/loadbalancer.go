package loadbalancer

import (
	"context"
	"fmt"
	"os"
	"time" // Do not use pkg/time in test code.

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	k8sclient "sigs.k8s.io/controller-runtime/pkg/client"

	"gke-internal.googlesource.com/third_party/cilium/google_test/wora/e2e/pkg/test/wait"

	klog "gke-internal.googlesource.com/syllogi/sanitized-klog/third_party/klogv2"
	e2escheme "gke-internal.googlesource.com/third_party/cilium/google_test/wora/e2e/pkg/test/scheme"
	"gke-internal.googlesource.com/third_party/cilium/google_test/wora/e2e/pkg/test/utils"
)

var (
	ctx          context.Context
	clientset    *kubernetes.Clientset
	cl           k8sclient.Client
	cleanupFuncs []func()
	testPods     []string
)

const (
	testNamespace = "loadbalancer"
	serviceName   = "lbservice1"
	pod1Name      = "lbservicetestpod1"
	pod2Name      = "lbservicetestpod2"
	servicePort   = 80
)

var _ = Describe("LoadBalancer", Label("loadbalancer"), Ordered, func() {
	BeforeAll(func() {
		s := e2escheme.Scheme()

		ctx, _ = context.WithTimeout(context.Background(), 10*time.Minute)

		kubeconfig := os.Getenv("KUBECONFIG")

		config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
		Expect(err).NotTo(HaveOccurred())

		clientset, err = kubernetes.NewForConfig(config)
		Expect(err).NotTo(HaveOccurred())

		cl, err = k8sclient.New(config, k8sclient.Options{Scheme: s})
		Expect(err).NotTo(HaveOccurred())
		// Create the test namespace
		err = utils.CreateTestNamespace(ctx, cl, testNamespace)
		Expect(err).NotTo(HaveOccurred())

		// Create the load balancer service with backend pods
		err = utils.CreateLBService(ctx, cl, serviceName, testNamespace, serviceName, servicePort, 8080)
		Expect(err).NotTo(HaveOccurred())
	})

	AfterAll(func() {
		// Delete the load balancer service created for the test
		klog.Infof("Deleting load balancer service %s", serviceName)
		service := &corev1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name:      serviceName,
				Namespace: testNamespace,
			},
		}
		err := utils.DeleteIfExists(ctx, cl, service)
		Expect(err).NotTo(HaveOccurred())

		// Delete the test namespace
		klog.Infof("Deleting test namespace %s", testNamespace)
		ns := &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name: testNamespace,
			},
		}
		err = utils.DeleteIfExists(ctx, cl, ns)
		Expect(err).NotTo(HaveOccurred())
	})

	AfterEach(func() {
		// Delete backend after every test case
		klog.Infof("deleting pods in namespace %s", testNamespace)
		testDescription := CurrentGinkgoTestDescription()
		if testDescription.Failed {
			pods, err := clientset.CoreV1().Pods("loadbalancer").List(context.Background(), metav1.ListOptions{LabelSelector: serviceName})
			Expect(err).NotTo(HaveOccurred())
			for _, pod := range pods.Items {
				podLogs, err := utils.FetchPodLogs(ctx, clientset, pod.Name, testNamespace)
				if err != nil {
					klog.Errorf("Failed to fetch logs for pod %s: %v", pod.Name, err)
				} else {
					klog.Infof("Logs for pod %s: %s", pod.Name, podLogs)
				}
			}
		}

		// Execute all cleanup functions
		for _, cleanup := range cleanupFuncs {
			cleanup()
		}

		// Making sure pods were deleted successfully
		for _, podName := range testPods {
			err := utils.WaitForPodDeletion(ctx, cl, podName, testNamespace)
			Expect(err).ToNot(HaveOccurred())
		}
		cleanupFuncs = nil
		testPods = []string{}
	})

	It("Verifies IPv4 LoadBalancer connectivity from bootstrap", func() {
		err := createBackends(false, false)
		Expect(err).ToNot(HaveOccurred())
		err = testLoadBalancerService()
		Expect(err).ToNot(HaveOccurred())
	})

	It("Verifies IPv4 LoadBalancer connectivity from bootstrap with hostNetwork Backend and anti-affinity", func() {
		err := createBackends(true, true)
		Expect(err).ToNot(HaveOccurred())
		err = testLoadBalancerService()
		Expect(err).ToNot(HaveOccurred())
	})

})

// testLoadBalanceService function
//   - validate NodePort is working correctly for all the nodes.
//   - ensure that lbservice is ready.
//   - run curl command from bootstrapper and ensure everything is in order.
func testLoadBalancerService() error {
	err := verifyNodePort()
	if err != nil {
		return err
	}

	err = utils.WaitForServiceReadiness(ctx, cl, serviceName, testNamespace, corev1.ServiceTypeLoadBalancer)
	if err != nil {
		return err
	}

	service := corev1.Service{}
	err = cl.Get(ctx, k8sclient.ObjectKey{Name: serviceName, Namespace: testNamespace}, &service)
	if err != nil {
		return err
	}

	for _, ingress := range service.Status.LoadBalancer.Ingress {
		err := utils.RunCurlFromBootstrapper(ctx, cl, ingress.IP, servicePort, wait.WaitingMedium)
		if err != nil {
			return err
		}
	}
	return nil
}

// verifyNodePort verifies the working of nodeport at each node.
func verifyNodePort() error {
	// Get nodes in the cluster.
	nodes, err := clientset.CoreV1().Nodes().List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		return err
	}
	if len(nodes.Items) == 0 {
		return fmt.Errorf("node list should not be empty.")
	}
	var nodeips []string
	for _, node := range nodes.Items {
		for _, address := range node.Status.Addresses {
			if address.Type == corev1.NodeInternalIP {
				nodeips = append(nodeips, address.Address)
			}
		}
	}

	// Wait for service NodePort to come up.
	err, nodeport := utils.NodePortReadiness(ctx, cl, serviceName, testNamespace, corev1.ServiceTypeLoadBalancer)
	if err != nil {
		return err
	}
	for _, nodeip := range nodeips {
		url := fmt.Sprintf("http://%s:%d", nodeip, nodeport)
		klog.Infof("Attempting to connect to NodePort service via URL: %s", url)
		err := utils.RunCurlFromBootstrapper(ctx, cl, nodeip, nodeport, wait.WaitingMedium)
		if err != nil {
			klog.Errorf("Failed to connect to NodePort service via URL %s: %v", url, err)
			return err
		}
	}
	return nil
}

func createBackends(preventSchedulingOnLBNode bool, hostNetworkBackend bool) error {
	// Create backend pods with desired config
	affinity := &corev1.Affinity{
		PodAntiAffinity: &corev1.PodAntiAffinity{
			PreferredDuringSchedulingIgnoredDuringExecution: []corev1.WeightedPodAffinityTerm{
				{
					Weight: 100,
					PodAffinityTerm: corev1.PodAffinityTerm{
						LabelSelector: &metav1.LabelSelector{
							MatchLabels: map[string]string{
								"app": "lbservice1",
							},
						},
						TopologyKey: "kubernetes.io/hostname",
					},
				},
			},
		},
	}
	if preventSchedulingOnLBNode {
		affinity.NodeAffinity = &corev1.NodeAffinity{
			RequiredDuringSchedulingIgnoredDuringExecution: &corev1.NodeSelector{
				NodeSelectorTerms: []corev1.NodeSelectorTerm{
					{
						MatchExpressions: []corev1.NodeSelectorRequirement{
							{
								Key:      "baremetal.cluster.gke.io/lbnode",
								Operator: corev1.NodeSelectorOpNotIn,
								Values:   []string{"true"},
							},
						},
					},
				},
			},
		}
	}
	if hostNetworkBackend {
		cleanup1, err := utils.CreatePod(ctx, cl, pod1Name, testNamespace,
			utils.WithLabel("app", serviceName),
			utils.WithResponderContainer(),
			utils.WithAffinity(affinity),
			utils.WithHostNetworking())
		if err != nil {
			return err
		}
		testPods = append(testPods, pod1Name)
		cleanupFuncs = append(cleanupFuncs, cleanup1)

		cleanup2, err := utils.CreatePod(ctx, cl, pod2Name, testNamespace,
			utils.WithLabel("app", serviceName),
			utils.WithResponderContainer(),
			utils.WithAffinity(affinity),
			utils.WithHostNetworking())
		if err != nil {
			return err
		}
		testPods = append(testPods, pod2Name)
		cleanupFuncs = append(cleanupFuncs, cleanup2)
	} else {
		cleanup1, err := utils.CreatePod(ctx, cl, pod1Name, testNamespace,
			utils.WithLabel("app", serviceName),
			utils.WithResponderContainer(),
			utils.WithAffinity(affinity))
		if err != nil {
			return err
		}
		testPods = append(testPods, pod1Name)
		cleanupFuncs = append(cleanupFuncs, cleanup1)

		cleanup2, err := utils.CreatePod(ctx, cl, pod2Name, testNamespace,
			utils.WithLabel("app", serviceName),
			utils.WithResponderContainer(),
			utils.WithAffinity(affinity))
		if err != nil {
			return err
		}
		testPods = append(testPods, pod2Name)
		cleanupFuncs = append(cleanupFuncs, cleanup2)
	}
	return nil
}
