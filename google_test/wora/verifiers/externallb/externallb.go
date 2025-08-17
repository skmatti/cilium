package externallb

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
	backendpod                   = "lb-endpoint-pod"
	perimeterVM                  = "perimeter-vm"
	backendVM                    = "lb-endpoint-vm"
	testNamespace                = "externallb"
	perimeterNetworkName         = "g-org-1-perimeter-cluster-internal"
	perimeterExternalNetworkName = "g-org-1-perimeter-cluster-external"
	defaultNetworkName           = "g-default-vpc"
)

var _ = Describe("ExternalLB", Label("externallb"), Ordered, func() {
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
		Expect(err).NotTo(HaveOccurred(), "Failed to create Kubernetes client")
		// Create the test namespace
		err = utils.CreateTestNamespace(ctx, cl, testNamespace)
		Expect(err).NotTo(HaveOccurred(), "Failed to create test namespace")

		ipamMode := networkv1.ExternalMode
		gateway := "192.168.0.1"
		nodeIntf := "vxlan0"
		vxlan1 := "vxlan1"
		externalGatway := "192.168.0.2"

		l3PerimeterNetworkInternal := networkv1.Network{
			ObjectMeta: metav1.ObjectMeta{
				Name: perimeterNetworkName,
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
					{
						To: "10.200.0.0/24",
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
		err = cl.Create(ctx, &l3PerimeterNetworkInternal)
		if err != nil && !apierrors.IsAlreadyExists(err) {
			Expect(err).NotTo(HaveOccurred(), "Failed to create l3 network")
		}

		l3PerimeterNetworkExternal := networkv1.Network{
			ObjectMeta: metav1.ObjectMeta{
				Name: perimeterExternalNetworkName,
			},
			Spec: networkv1.NetworkSpec{
				Type:     networkv1.L2NetworkType,
				IPAMMode: &ipamMode,
				DNSConfig: &networkv1.DNSConfig{
					Nameservers: []string{"172.26.0.10"},
				},
				Gateway4: &externalGatway,
				NodeInterfaceMatcher: networkv1.NodeInterfaceMatcher{
					InterfaceName: &vxlan1,
				},
			},
		}
		err = cl.Create(ctx, &l3PerimeterNetworkExternal)
		if err != nil && !apierrors.IsAlreadyExists(err) {
			Expect(err).NotTo(HaveOccurred(), "Failed to create l3 network")
		}

		l3DefaultNetwork := networkv1.Network{
			ObjectMeta: metav1.ObjectMeta{
				Name: defaultNetworkName,
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
						To: "10.248.0.1/24",
					},
					{
						To: "127.0.0.0/1",
					},
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
		err = cl.Create(ctx, &l3DefaultNetwork)
		if err != nil && !apierrors.IsAlreadyExists(err) {
			Expect(err).NotTo(HaveOccurred(), "Failed to create l3 network")
		}
	})

	AfterAll(func() {
		klog.Infof("Deleting l3 perimeter internal netowrk %s", perimeterNetworkName)
		network := &networkv1.Network{
			ObjectMeta: metav1.ObjectMeta{
				Name: perimeterNetworkName,
			},
		}
		err = utils.DeleteAndWait(ctx, cl, network)
		Expect(err).NotTo(HaveOccurred())

		klog.Infof("Deleting l3 default netowrk %s", defaultNetworkName)
		network = &networkv1.Network{
			ObjectMeta: metav1.ObjectMeta{
				Name: defaultNetworkName,
			},
		}
		err = utils.DeleteAndWait(ctx, cl, network)
		Expect(err).NotTo(HaveOccurred())

		klog.Infof("Deleting l3 perimeter external netowrk %s", perimeterExternalNetworkName)
		network = &networkv1.Network{
			ObjectMeta: metav1.ObjectMeta{
				Name: perimeterExternalNetworkName,
			},
		}
		err = utils.DeleteAndWait(ctx, cl, network)
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
		failed := CurrentSpecReport().Failed()
		if failed {
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

	It("Verifies perimeter cluster traffic to pod on same node", func() {
		backendPodName := backendpod + "--same-node"
		perimeterVMName := perimeterVM + "--same-node"
		perimeterInternalIP := "192.168.0.100"
		perimeterExternalIP := "10.10.10.10"
		backendVMIP := "" // Not used for non-emulated pod

		podAffinity := &corev1.Affinity{
			PodAffinity: &corev1.PodAffinity{
				RequiredDuringSchedulingIgnoredDuringExecution: []corev1.PodAffinityTerm{
					{
						LabelSelector: &metav1.LabelSelector{
							MatchLabels: map[string]string{
								"app": backendPodName,
							},
						},
						TopologyKey: "kubernetes.io/hostname",
					},
				},
			},
		}
		emulatedL3VMPod := false
		testPods, cleanupFuncs, err = testELBLancerFromPod(ctx, cl, backendPodName, perimeterVMName, podAffinity, emulatedL3VMPod, backendVMIP, perimeterInternalIP, perimeterExternalIP)
		Expect(err).NotTo(HaveOccurred(), fmt.Sprintf("external traffic not able to reach %s via %s : %v", backendPodName, perimeterVMName, err))
	})

	It("Verifies perimeter cluster traffic to worker vm on same node", func() {
		backendVMName := backendVM + "--same-node"
		perimeterVMName := perimeterVM + "--same-node"
		perimeterInternalIP := "192.168.0.102"
		perimeterExternalIP := "10.10.10.11"
		backendVMIP := "192.168.0.103"

		podAffinity := &corev1.Affinity{
			PodAffinity: &corev1.PodAffinity{
				RequiredDuringSchedulingIgnoredDuringExecution: []corev1.PodAffinityTerm{
					{
						LabelSelector: &metav1.LabelSelector{
							MatchLabels: map[string]string{
								"app": backendVMName,
							},
						},
						TopologyKey: "kubernetes.io/hostname",
					},
				},
			},
		}
		emulatedL3VMPod := true
		testPods, cleanupFuncs, err = testELBLancerFromPod(ctx, cl, backendVMName, perimeterVMName, podAffinity, emulatedL3VMPod, backendVMIP, perimeterInternalIP, perimeterExternalIP)
		Expect(err).NotTo(HaveOccurred(), fmt.Sprintf("external traffic not able to reach %s via %s : %v", backendVMName, perimeterVMName, err))
	})

	It("Verifies perimeter cluster traffic to pod on different node", func() {
		backendPodName := backendpod + "--diff-node"
		perimeterVMName := perimeterVM + "--diff-node"
		perimeterInternalIP := "192.168.0.104"
		perimeterExternalIP := "10.10.10.12"
		backendVMIP := "" // Not used for non-emulated pod

		podAntiAffinity := &corev1.Affinity{
			PodAntiAffinity: &corev1.PodAntiAffinity{
				RequiredDuringSchedulingIgnoredDuringExecution: []corev1.PodAffinityTerm{
					{
						LabelSelector: &metav1.LabelSelector{
							MatchLabels: map[string]string{
								"app": backendPodName,
							},
						},
						TopologyKey: "kubernetes.io/hostname",
					},
				},
			},
		}
		emulatedL3VMPod := false
		testPods, cleanupFuncs, err = testELBLancerFromPod(ctx, cl, backendPodName, perimeterVMName, podAntiAffinity, emulatedL3VMPod, backendVMIP, perimeterInternalIP, perimeterExternalIP)
		Expect(err).NotTo(HaveOccurred(), fmt.Sprintf("external traffic not able to reach %s via %s : %v", backendPodName, perimeterVMName, err))
	})

	It("Verifies perimeter cluster traffic to worker vm on different node", func() {
		backendVMName := backendVM + "--diff-node"
		perimeterVMName := perimeterVM + "--diff-node"
		perimeterInternalIP := "192.168.0.105"
		perimeterExternalIP := "10.10.10.13"
		backendVMIP := "192.168.0.106"

		podAntiAffinity := &corev1.Affinity{
			PodAntiAffinity: &corev1.PodAntiAffinity{
				RequiredDuringSchedulingIgnoredDuringExecution: []corev1.PodAffinityTerm{
					{
						LabelSelector: &metav1.LabelSelector{
							MatchLabels: map[string]string{
								"app": backendVMName,
							},
						},
						TopologyKey: "kubernetes.io/hostname",
					},
				},
			},
		}
		emulatedL3VMPod := true
		testPods, cleanupFuncs, err = testELBLancerFromPod(ctx, cl, backendVMName, perimeterVMName, podAntiAffinity, emulatedL3VMPod, backendVMIP, perimeterInternalIP, perimeterExternalIP)
		Expect(err).NotTo(HaveOccurred(), fmt.Sprintf("external traffic not able to reach %s via %s : %v", backendVMName, perimeterVMName, err))
	})
})

// testELBLancerFromPod created perimeter vm and a backend pod and verifies the connectivity from perimeter vm to backend pod
func testELBLancerFromPod(ctx context.Context, cl k8sclient.Client, backendPodName, perimeterVMName string, affinity *corev1.Affinity, isEmulatedL3VMPod bool, backendVMIP, perimeterInternalIP, perimeterExternalIP string) ([]string, []func(), error) {
	var testPods []string
	var cleanupFuncs []func()
	var cleanupBackendPod func()
	var err error
	var podBackendIP string

	if isEmulatedL3VMPod {
		cleanupBackendPod, err = createEmulatedL3VMPod(ctx, cl, backendPodName, testNamespace, backendVMIP, utils.WithLabel("app", backendPodName), utils.WithResponderContainer())
		if err != nil {
			cleanupFuncs = append(cleanupFuncs, cleanupBackendPod)
			return testPods, cleanupFuncs, fmt.Errorf("failed to create emulated L3 VM pod %s: %v", backendPodName, err)
		}
		podBackendIP = backendVMIP
	} else {
		cleanupBackendPod, err = utils.CreatePod(ctx, cl, backendPodName, testNamespace, utils.WithLabel("app", backendPodName), utils.WithResponderContainer())
		if err != nil {
			cleanupFuncs = append(cleanupFuncs, cleanupBackendPod)
			return testPods, cleanupFuncs, fmt.Errorf("failed to create pod %s: %v", backendPodName, err)
		}
		podBackendIP, err = utils.FetchPodIP(ctx, cl, backendPodName, testNamespace)
		if err != nil {
			cleanupFuncs = append(cleanupFuncs, cleanupBackendPod)
			testPods = append(testPods, backendPodName)
			return testPods, cleanupFuncs, fmt.Errorf("failed to fetch ip for pod %s: %v", backendPodName, err)
		}
	}
	testPods = append(testPods, backendPodName)
	cleanupFuncs = append(cleanupFuncs, cleanupBackendPod)

	cmds := []string{}
	cleanup, err := createEmulatedPerimeterVMPod(ctx, cl, perimeterVMName, testNamespace, perimeterInternalIP, perimeterExternalIP, cmds, utils.WithLabel("app", perimeterVMName), utils.WithAffinity(affinity))
	if err != nil {
		cleanupFuncs = append(cleanupFuncs, cleanup)
		return testPods, cleanupFuncs, fmt.Errorf("failed to create vm pod %s with affinity: %v", perimeterVMName, err)
	}
	testPods = append(testPods, perimeterVMName)
	cleanupFuncs = append(cleanupFuncs, cleanup)

	// Verify ELB traffic
	klog.Infof("Running curl from perimeter vm %s:%s to backend pod %s:%s", perimeterVMName, perimeterInternalIP, backendPodName, podBackendIP)
	err = utils.VerifyCurlFromPod(ctx, testNamespace, perimeterVMName, podBackendIP, 8080, true, backendPodName)
	if err != nil {
		return testPods, cleanupFuncs, fmt.Errorf("perimeter vm %s is not able to connect to backend %s: %v", perimeterVMName, backendPodName, err)
	}
	return testPods, cleanupFuncs, nil
}

// createEmulatedPerimeterMPod creates a pod with three interfaces (eth0 and eth1, eth2).
func createEmulatedPerimeterVMPod(ctx context.Context, cl k8sclient.Client, podName, ns, ip, externalIP string, cmds []string, opts ...utils.PodCustomization) (func(), error) {
	networkInfos := []utils.NetworkInfo{
		{
			InterfaceName: "eth0",
			NetworkName:   "pod-network",
		},
		{
			InterfaceName: "eth1",
			NetworkName:   perimeterNetworkName,
			IPAddress:     ip,
			IsDefault:     true,
		},
		{
			InterfaceName: "eth2",
			NetworkName:   perimeterExternalNetworkName,
			IPAddress:     externalIP,
		},
	}
	opts = append(opts, utils.WithAnnotation("networking.gke.io/disable-source-ip-validation", "true"))
	return utils.CreatePodWithNetworkInterfaces(ctx, cl, podName, ns, networkInfos, cmds, opts...)
}

// createEmulatedL3VMPod creates a pod with two interfaces (eth0 and eth1).
func createEmulatedL3VMPod(ctx context.Context, cl k8sclient.Client, podName, ns, ip string, opts ...utils.PodCustomization) (func(), error) {
	networkInfos := []utils.NetworkInfo{
		{
			InterfaceName: "eth0",
			NetworkName:   "pod-network",
		},
		{
			InterfaceName: "eth1",
			NetworkName:   defaultNetworkName,
			IPAddress:     ip,
			IsDefault:     true,
		},
	}
	return utils.CreatePodWithNetworkInterfaces(ctx, cl, podName, ns, networkInfos, nil, opts...)
}
