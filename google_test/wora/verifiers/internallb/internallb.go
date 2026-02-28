package internallb

import (
	"context"
	"fmt"
	"os"
	"time" // Do not use pkg/time in test code.

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	networkv1 "k8s.io/cloud-provider-gcp/crd/apis/network/v1"
	k8sclient "sigs.k8s.io/controller-runtime/pkg/client"

	klog "gke-internal.googlesource.com/syllogi/sanitized-klog/third_party/klogv2"
	e2escheme "gke-internal.googlesource.com/third_party/cilium/google_test/wora/e2e/pkg/test/scheme"
	"gke-internal.googlesource.com/third_party/cilium/google_test/wora/e2e/pkg/test/utils"
	"gke-internal.googlesource.com/third_party/cilium/google_test/wora/e2e/pkg/test/wait"
)

const (
	backendpod    = "lb-endpoint-pod"
	workerVM      = "worker-vm"
	workerPod     = "worker-pod"
	testNamespace = "internallb"
	networkName   = "g-default-vpc"
	serviceName   = "internallb"
	servicePort   = 80
)

var _ = Describe("InternalLB", Label("internallb"), Ordered, func() {
	var (
		cl           k8sclient.Client
		err          error
		testPods     []string
		cleanupFuncs []func()
		ctx          context.Context
		clientset    *kubernetes.Clientset
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
		Expect(err).NotTo(HaveOccurred())
		// Create the test namespace
		err = utils.CreateTestNamespace(ctx, cl, testNamespace)
		Expect(err).NotTo(HaveOccurred(), "Failed to create test namespace")

		ipamMode := networkv1.ExternalMode
		gateway := "192.168.0.1"
		nodeIntf := "vxlan0"
		l3Network := networkv1.Network{
			ObjectMeta: metav1.ObjectMeta{
				Name: networkName,
			},
			Spec: networkv1.NetworkSpec{
				Type:     networkv1.L3NetworkType,
				IPAMMode: &ipamMode,
				DNSConfig: &networkv1.DNSConfig{
					Nameservers: []string{"172.26.0.10"},
				},
				Gateway4: &gateway,
				Routes: []networkv1.Route{
					// More specific routes for pod-network and service in the cluster.
					// Those routes ensure all cluster traffic also go through the l3-veth interface
					// on those emulated vm pods.
					{
						To: "10.240.0.0/16",
					},
					{
						To: "172.26.0.0/17",
					},
					{
						To: "172.26.128.0/17",
					},
					// All emulated vm pods should staty in the following subnet.
					{
						To: "192.168.0.0/24",
					},
				},
				NodeInterfaceMatcher: networkv1.NodeInterfaceMatcher{
					InterfaceName: &nodeIntf,
				},
			},
		}

		err = cl.Create(ctx, &l3Network)
		if err != nil && !apierrors.IsAlreadyExists(err) {
			Expect(err).NotTo(HaveOccurred(), "Failed to create l3 network")
		}

		// Create the internal load balancer service
		err = utils.CreateLBService(ctx, cl, serviceName, testNamespace, serviceName, servicePort, int(8080))
		Expect(err).NotTo(HaveOccurred())
	})

	AfterAll(func() {
		klog.Infof("Deleting l3 network %s", networkName)
		network := &networkv1.Network{
			ObjectMeta: metav1.ObjectMeta{
				Name: networkName,
			},
		}
		err := utils.DeleteAndWait(ctx, cl, network)
		Expect(err).NotTo(HaveOccurred())

		// Delete the load balancer service created for the test
		klog.Infof("Deleting load balancer service %s", serviceName)
		service := &corev1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name:      serviceName,
				Namespace: testNamespace,
			},
		}
		err = utils.DeleteIfExists(ctx, cl, service)
		Expect(err).NotTo(HaveOccurred())

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
		if CurrentSpecReport().Failed() {
			// Collect logs for all test pods if the test failed
			for _, podName := range testPods {
				podLogs, err := utils.FetchPodLogs(ctx, clientset, podName, testNamespace)
				if err != nil {
					klog.Errorf("Failed to fetch logs for pod %s: %v", podName, err)
				} else {
					klog.Infof("Logs for pod %s: %s", podName, podLogs)
				}
			}
		}

		// Execute all cleanup functions
		for _, cleanup := range cleanupFuncs {
			cleanup()
		}
		// Validate all pods are deleted before next test
		for _, podName := range testPods {
			err := wait.WaitForSuccessContext(ctx, "Delete pod", wait.WaitingMedium, func(ctx context.Context) error {
				pod := &corev1.Pod{}
				getErr := cl.Get(ctx, k8sclient.ObjectKey{Name: podName, Namespace: testNamespace}, pod)
				if getErr != nil {
					if apierrors.IsNotFound(getErr) {
						klog.Infof("Pod %s deleted successfully", podName)
						return nil
					}
					return getErr
				}
				return fmt.Errorf("pod %s still exists and was not deleted successfully", podName)
			})
			Expect(err).NotTo(HaveOccurred(), "Failed to wait for pod deletion for pod %s", podName)
		}
		// Reset cleanupFuncs and testPods before next test
		cleanupFuncs = nil
		testPods = []string{}
	})

	It("Verify ILB behavior from a worker pod", func() {
		workerPodName := workerPod
		workerVMIP := "" // Not used for pod
		testPods, cleanupFuncs, err = testInternalLB(ctx, cl, workerPodName, workerVMIP, false, false)
		Expect(err).NotTo(HaveOccurred())
	})

	It("Verify ILB behavior from a worker vm", func() {
		workerPodName := workerVM
		workerVMIP := "192.168.0.100"
		testPods, cleanupFuncs, err = testInternalLB(ctx, cl, workerPodName, workerVMIP, true, false)
		Expect(err).NotTo(HaveOccurred())
	})

	It("Verify ILB behavior from a worker pod with backend on cp node", func() {
		workerPodName := workerPod
		workerVMIP := "" // Not used for pod
		testPods, cleanupFuncs, err = testInternalLB(ctx, cl, workerPodName, workerVMIP, false, true)
		Expect(err).NotTo(HaveOccurred())
	})

	It("Verify ILB behavior from a worker vm with backend on cp node", func() {
		workerPodName := workerVM
		workerVMIP := "192.168.0.101"
		testPods, cleanupFuncs, err = testInternalLB(ctx, cl, workerPodName, workerVMIP, true, true)
		Expect(err).NotTo(HaveOccurred())
	})
})

func testInternalLB(ctx context.Context, cl k8sclient.Client, workerPodName, workerVMIP string, isEmulatedl3Pod, sameNode bool) ([]string, []func(), error) {
	var testPods []string
	var cleanupFuncs []func()
	var cleanupFunc func()
	var err error

	affinity := &corev1.Affinity{}

	cleanupFunc, err = utils.CreatePod(ctx, cl, backendpod, testNamespace, utils.WithLabel("app", serviceName), utils.WithResponderContainer())
	cleanupFuncs = append(cleanupFuncs, cleanupFunc)
	if err != nil {
		return testPods, cleanupFuncs, fmt.Errorf("failed to create backend pod %s: %v", backendpod, err)
	}
	testPods = append(testPods, backendpod)
	if sameNode {
		affinity.PodAffinity = &corev1.PodAffinity{
			RequiredDuringSchedulingIgnoredDuringExecution: []corev1.PodAffinityTerm{
				{
					LabelSelector: &metav1.LabelSelector{
						MatchLabels: map[string]string{
							"app": serviceName,
						},
					},
					TopologyKey: "kubernetes.io/hostname",
				},
			},
		}
	} else {
		affinity.PodAntiAffinity = &corev1.PodAntiAffinity{
			RequiredDuringSchedulingIgnoredDuringExecution: []corev1.PodAffinityTerm{
				{
					LabelSelector: &metav1.LabelSelector{
						MatchLabels: map[string]string{
							"app": serviceName,
						},
					},
					TopologyKey: "kubernetes.io/hostname",
				},
			},
		}
	}
	if isEmulatedl3Pod {
		cleanupFunc, err = createEmulatedL3VMPod(ctx, cl, workerPodName, workerVMIP, utils.WithLabel("app", "worker"), utils.WithAffinity(affinity))
	} else {
		cleanupFunc, err = utils.CreatePod(ctx, cl, workerPodName, testNamespace, utils.WithLabel("app", "worker"), utils.WithAffinity(affinity))
	}
	cleanupFuncs = append(cleanupFuncs, cleanupFunc)
	if err != nil {
		return testPods, cleanupFuncs, fmt.Errorf("failed to create worker pod/vm %s: %v", workerPodName, err)
	}
	testPods = append(testPods, workerPodName)

	err = utils.WaitForServiceReadiness(ctx, cl, serviceName, testNamespace, corev1.ServiceTypeLoadBalancer)
	if err != nil {
		return testPods, cleanupFuncs, err
	}

	service := corev1.Service{}
	err = cl.Get(ctx, k8sclient.ObjectKey{Name: serviceName, Namespace: testNamespace}, &service)
	if err != nil {
		return testPods, cleanupFuncs, err
	}

	for _, ingress := range service.Status.LoadBalancer.Ingress {
		err = utils.VerifyCurlFromPod(ctx, testNamespace, workerPodName, ingress.IP, servicePort, true, backendpod)
		if err != nil {
			return testPods, cleanupFuncs, fmt.Errorf("failed to verify curl to service IP %s: %v", ingress.IP, err)
		}
	}
	return testPods, cleanupFuncs, nil
}

// createEmulatedL3VMPod creates a pod with two interfaces (eth0 and eth1).
func createEmulatedL3VMPod(ctx context.Context, cl k8sclient.Client, podName, ip string, opts ...utils.PodCustomization) (func(), error) {
	networkInfos := []utils.NetworkInfo{
		{
			InterfaceName: "eth0",
			NetworkName:   "pod-network",
		},
		{
			InterfaceName: "eth1",
			NetworkName:   networkName,
			IPAddress:     ip,
			IsDefault:     true,
		},
	}
	return utils.CreatePodWithNetworkInterfaces(ctx, cl, podName, testNamespace, networkInfos, nil, opts...)
}
