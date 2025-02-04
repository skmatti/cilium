// L3 VM is only supported in the GDC-AG cluster.
// So the test uses multi-networking pod with veth to simulate l3 vm.
package l3vm

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
	l3VMPodName1  = "vm1"
	l3VMIP1       = "192.168.0.100"
	l3VMPodName2  = "vm2"
	l3VMIP2       = "192.168.0.110"
	curlJobName   = "curl-job"
	testNamespace = "l3vm"
	networkName   = "g-default-vpc"
)

var _ = Describe("Verifiers/L3VM", Label("l3vm"), Ordered, func() {
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
	})

	AfterAll(func() {
		klog.Infof("Deleting l3 network %s", networkName)
		network := &networkv1.Network{
			ObjectMeta: metav1.ObjectMeta{
				Name: networkName,
			},
		}
		err := utils.DeleteAndWait(ctx, cl, network, "network")
		Expect(err).NotTo(HaveOccurred())

		klog.Infof("Deleting test namespace %s", testNamespace)
		ns := &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name: testNamespace,
			},
		}
		err = utils.DeleteIfExists(ctx, cl, ns, "namespace")
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
			err = utils.WaitForPodDeletion(ctx, cl, podName, testNamespace)
		}

		// Reset cleanupFuncs and testPods before next test
		cleanupFuncs = nil
		testPods = []string{}
	})

	It("Verifies emulated l3 vm pods should reach each other on same node", func() {
		testPod1Name := l3VMPodName1 + "-same-node"
		testPod2Name := l3VMPodName2 + "-same-node"
		// Add pod affinity to ensure the pod2 is scheduled on the same node as pod1.
		podAffinity := &corev1.Affinity{
			PodAffinity: &corev1.PodAffinity{
				RequiredDuringSchedulingIgnoredDuringExecution: []corev1.PodAffinityTerm{
					{
						LabelSelector: &metav1.LabelSelector{
							MatchLabels: map[string]string{
								"app": testPod1Name,
							},
						},
						TopologyKey: "kubernetes.io/hostname",
					},
				},
			},
		}

		testPods, cleanupFuncs, err = testConnectivityBetweenPods(ctx, cl, testPod1Name, testPod2Name, l3VMIP1, l3VMIP2, podAffinity)
		Expect(err).NotTo(HaveOccurred(), fmt.Sprintf("pod %s is not able to reach pod %s", testPod1Name, testPod2Name))
	})

	It("Verifies emulated l3 vm pods should reach each other on different nodes", func() {
		testPod1Name := l3VMPodName1 + "-diff-nodes"
		testPod2Name := l3VMPodName2 + "-diff-nodes"
		// Add pod anti-affinity to ensure the pod2 is scheduled on different nodes as pod1.
		podAntiAffinity := &corev1.Affinity{
			PodAntiAffinity: &corev1.PodAntiAffinity{
				RequiredDuringSchedulingIgnoredDuringExecution: []corev1.PodAffinityTerm{
					{
						LabelSelector: &metav1.LabelSelector{
							MatchLabels: map[string]string{
								"app": testPod1Name,
							},
						},
						TopologyKey: "kubernetes.io/hostname",
					},
				},
			},
		}

		testPods, cleanupFuncs, err = testConnectivityBetweenPods(ctx, cl, testPod1Name, testPod2Name, l3VMIP1, l3VMIP2, podAntiAffinity)
		Expect(err).NotTo(HaveOccurred(), fmt.Sprintf("pod %s is not able to reach pod %s", testPod1Name, testPod2Name))
	})

	It("Verifies pod network should reach emulated l3 vm pod on different nodes", func() {
		testPodName := l3VMPodName1 + "-anti-affinity"
		cleanup, err := createEmulatedL3VMPod(ctx, cl, testPodName, testNamespace, l3VMIP1, utils.WithLabel("app", testPodName), utils.WithResponderContainer())
		Expect(err).NotTo(HaveOccurred(), "Failed to emulated l3 vm pod")
		testPods = append(testPods, testPodName)
		cleanupFuncs = append(cleanupFuncs, cleanup)

		job := utils.NewCurlJob(curlJobName+"-anti-affinity", l3VMIP1, testNamespace, utils.ResponderPort, testPodName)

		// Add anti-affinity to ensure the Job Pod is not scheduled on the same node as the target Pod
		job.Spec.Template.Spec.Affinity = &corev1.Affinity{
			PodAntiAffinity: &corev1.PodAntiAffinity{
				RequiredDuringSchedulingIgnoredDuringExecution: []corev1.PodAffinityTerm{
					{
						LabelSelector: &metav1.LabelSelector{
							MatchLabels: map[string]string{
								"app": testPodName,
							},
						},
						TopologyKey: "kubernetes.io/hostname",
					},
				},
			},
		}

		klog.Infof("Start anti-affinity curl job to IP %s", l3VMIP1)

		err = cl.Create(ctx, job)
		Expect(err).NotTo(HaveOccurred(), "Failed to create curl job")
		err = wait.WaitForSuccessContext(ctx, "Curl job complete", wait.WaitingMedium, func(ctx context.Context) error {
			if err := cl.Get(ctx, k8sclient.ObjectKeyFromObject(job), job); err != nil {
				return fmt.Errorf("get curl job: %w", err)
			}
			return utils.JobComplete(job)
		})
		Expect(err).NotTo(HaveOccurred(), "Job didn't complete")
	})

	It("Verifies pod network should reach emulated l3 vm pod on same node", func() {
		testPodName := l3VMPodName1 + "-affinity"
		cleanup, err := createEmulatedL3VMPod(ctx, cl, testPodName, testNamespace, l3VMIP1, utils.WithLabel("app", testPodName), utils.WithResponderContainer())
		Expect(err).NotTo(HaveOccurred(), "Failed to emulated l3 vm pod")
		testPods = append(testPods, testPodName)
		cleanupFuncs = append(cleanupFuncs, cleanup)

		job := utils.NewCurlJob(curlJobName+"-affinity", l3VMIP1, testNamespace, 8080, testPodName)

		// Add anti-affinity to ensure the Job Pod is not scheduled on the same node as the target Pod
		job.Spec.Template.Spec.Affinity = &corev1.Affinity{
			PodAffinity: &corev1.PodAffinity{
				RequiredDuringSchedulingIgnoredDuringExecution: []corev1.PodAffinityTerm{
					{
						LabelSelector: &metav1.LabelSelector{
							MatchLabels: map[string]string{
								"app": testPodName,
							},
						},
						TopologyKey: "kubernetes.io/hostname",
					},
				},
			},
		}

		klog.Infof("Start affinity curl job to IP %s", l3VMIP1)
		err = cl.Create(ctx, job)
		Expect(err).NotTo(HaveOccurred(), "Failed to create curl job")
		err = wait.WaitForSuccessContext(ctx, "Curl job complete", wait.WaitingMedium, func(ctx context.Context) error {
			if err := cl.Get(ctx, k8sclient.ObjectKeyFromObject(job), job); err != nil {
				return fmt.Errorf("get curl job: %w", err)
			}
			return utils.JobComplete(job)
		})
		Expect(err).NotTo(HaveOccurred(), "Job didn't complete")
	})
})

// createEmulatedL3VMPod creates a pod with two interfaces (eth0 and eth1).
func createEmulatedL3VMPod(ctx context.Context, cl k8sclient.Client, podName, ns, ip string, opts ...utils.PodCustomization) (func(), error) {
	networkInfos := []utils.NetworkInfo{
		{
			InterfaceName: "eth0",
			NetworkName:   "pod-network",
		},
		{
			InterfaceName: "eth1",
			NetworkName:   "g-default-vpc",
			IPAddress:     ip,
		},
	}

	return utils.CreatePodWithNetworkInterfaces(ctx, cl, podName, ns, networkInfos, nil, opts...)
}

func testConnectivityBetweenPods(ctx context.Context, cl k8sclient.Client, pod1, pod2, pod1IP, pod2IP string, affinity *corev1.Affinity) ([]string, []func(), error) {
	var testPods []string
	var cleanupFuncs []func()
	cleanup1, err := createEmulatedL3VMPod(ctx, cl, pod1, testNamespace, pod1IP, utils.WithLabel("app", pod1), utils.WithResponderContainer())
	if err != nil {
		return testPods, cleanupFuncs, fmt.Errorf("failed to create vm pod %s: %v", pod1, err)
	}
	testPods = append(testPods, pod1)
	cleanupFuncs = append(cleanupFuncs, cleanup1)

	cleanup2, err := createEmulatedL3VMPod(ctx, cl, pod2, testNamespace, pod2IP, utils.WithLabel("app", pod2), utils.WithResponderContainer(), utils.WithAffinity(affinity))
	if err != nil {
		return testPods, cleanupFuncs, fmt.Errorf("failed to create vm pod %s with affinity: %v", pod2, err)
	}
	testPods = append(testPods, pod2)
	cleanupFuncs = append(cleanupFuncs, cleanup2)

	klog.Infof("Running curl from pod %s:%s to pod %s:%s", pod1, pod1IP, pod2, pod2IP)
	err = utils.VerifyCurlFromPod(ctx, cl, pod1, pod2, pod2IP, utils.ResponderPort, testNamespace, true)
	if err != nil {
		return testPods, cleanupFuncs, fmt.Errorf("pod %s is not able to reach pod %s: %v", pod1, pod2, err)
	}
	return testPods, cleanupFuncs, nil
}
