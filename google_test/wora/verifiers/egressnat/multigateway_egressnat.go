// GDC-ag multigateway-egressnat test
// The test uses multi-networking pod with veth to simulate premier cluster.
// It similar the dataplane of Infra Cluster
package egressnat

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
	gatewayNamespace      = "multigateway-egressnat"
	appSelectorLabelKey   = "app"
	appSelectorLabelValue = "val-1"
	numSourcePods         = 2
	gatewayName           = "gateway-1"
)

var (
	EgressNATIPs = []string{"10.200.32.16", "10.200.32.17"}
)

type TestContext struct {
	Client           k8sclient.Client
	Clientset        *kubernetes.Clientset
	Context          context.Context
	CleanupFuncs     []func()
	TestPods         []string
	GatewayNodeNames []string
	GatewayNodeIPs   []string
}

func InitTestContext(ctx context.Context) (TestContext, error) {
	s := e2escheme.SchemeV2()
	testCtx := TestContext{Context: ctx}

	kubeconfig := os.Getenv("KUBECONFIG")
	config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		return testCtx, err
	}

	testCtx.Clientset, err = kubernetes.NewForConfig(config)
	if err != nil {
		return testCtx, fmt.Errorf("failed to create Kubernetes clientset: %w", err)
	}

	testCtx.Client, err = k8sclient.New(config, k8sclient.Options{Scheme: s})
	if err != nil {
		return testCtx, fmt.Errorf("failed to create Kubernetes client: %w", err)
	}
	return testCtx, nil
}

func SetupTestEnvironment(ctx context.Context, cl k8sclient.Client, enablePerimeterNet bool, tc *TestContext) error {
	// Create the test namespace
	if err := utils.CreateTestNamespace(ctx, cl, gatewayNamespace); err != nil {
		return fmt.Errorf("failed to create test namespace: %w", err)
	}

	ipamMode := networkv1.ExternalMode
	gateway := "192.168.0.1"
	nodeIntf := "vxlan0"

	l3DefaultNetwork := networkv1.Network{
		ObjectMeta: metav1.ObjectMeta{Name: defaultNetworkName},
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
				{To: "10.248.0.1/24"},
				{To: "127.0.0.0/1"},
				{To: "10.240.0.0/16"},
				{To: "172.26.0.0/17"},
				{To: "172.26.128.0/17"},
				// All emulated vm pods should staty in the following subnet.
				{To: "192.168.0.0/24"},
			},
			NodeInterfaceMatcher: networkv1.NodeInterfaceMatcher{InterfaceName: &nodeIntf},
		},
	}
	err := cl.Create(ctx, &l3DefaultNetwork)
	if err != nil && !apierrors.IsAlreadyExists(err) {
		return fmt.Errorf("failed to create l3 default network: %w", err)
	}

	if enablePerimeterNet {
		l3PerimeterNetwork := networkv1.Network{
			ObjectMeta: metav1.ObjectMeta{Name: perimeterNetworkName},
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
					{To: "10.240.0.0/16"},
					{To: "172.26.0.0/17"},
					{To: "172.26.128.0/17"},
					// All emulated vm pods should staty in the following subnet.
					{To: "192.168.0.0/24"},
				},
				NodeInterfaceMatcher: networkv1.NodeInterfaceMatcher{InterfaceName: &nodeIntf},
			},
		}
		err = cl.Create(ctx, &l3PerimeterNetwork)
		if err != nil && !apierrors.IsAlreadyExists(err) {
			return fmt.Errorf("failed to create l3 perimeter network: %w", err)
		}
	} else {
		// Get target cloudNAT node
		workerNodes, err := utils.GetNodeListByLabel(ctx, cl, workerNodeLabel)
		if err == nil && len(workerNodes.Items) > 0 {
			for _, node := range workerNodes.Items {
				tc.GatewayNodeNames = append(tc.GatewayNodeNames, node.Name)
				if len(node.Status.Addresses) > 0 {
					tc.GatewayNodeIPs = append(tc.GatewayNodeIPs, node.Status.Addresses[0].Address)
				}
			}
		}
	}

	return nil
}

func CleanupTestEnvironment(cl k8sclient.Client, cleanupPerimeterNet bool) error {
	cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	if cleanupPerimeterNet {
		klog.Infof("Deleting l3 perimeter network %s", perimeterNetworkName)
		network := &networkv1.Network{ObjectMeta: metav1.ObjectMeta{Name: perimeterNetworkName}}
		if err := utils.DeleteAndWait(cleanupCtx, cl, network); err != nil {
			return err
		}
	}
	klog.Infof("Deleting l3 default network %s", defaultNetworkName)
	network := &networkv1.Network{ObjectMeta: metav1.ObjectMeta{Name: defaultNetworkName}}
	if err := utils.DeleteAndWait(cleanupCtx, cl, network); err != nil {
		return err
	}

	klog.Infof("Deleting test namespace %s", gatewayNamespace)
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: gatewayNamespace}}
	if err := utils.DeleteIfExists(cleanupCtx, cl, ns); err != nil {
		return err
	}
	return nil
}

func CleanupAfterEach(cl k8sclient.Client, clientset *kubernetes.Clientset, testPods []string, cleanupFuncs []func()) {
	cleanupCtx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	if CurrentSpecReport().Failed() {
		// Collect logs for all test pods if the test failed
		for _, podName := range testPods {
			podLogs, err := utils.FetchPodLogs(cleanupCtx, clientset, podName, gatewayNamespace)
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
		err := wait.WaitForSuccessContext(cleanupCtx, "Delete pod", wait.WaitingMedium, func(ctx context.Context) error {
			pod := &corev1.Pod{}
			getErr := cl.Get(ctx, k8sclient.ObjectKey{Name: podName, Namespace: gatewayNamespace}, pod)
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
}

var _ = Describe("Verifiers/EgressNAT", Label("multigateway_egressnat"), Ordered, func() {
	var tc TestContext

	BeforeAll(func() {
		var err error
		tc, err = InitTestContext(context.Background())
		Expect(err).NotTo(HaveOccurred(), "Failed to initialize test context")

		var ctx context.Context
		ctx, _ = context.WithTimeout(context.Background(), 20*time.Minute)
		tc.Context = ctx

		// Setup environment to include Perimeter Network
		err = SetupTestEnvironment(tc.Context, tc.Client, true, &tc)
		Expect(err).NotTo(HaveOccurred(), "Failed to set up test environment")
	})

	AfterAll(func() {
		err := CleanupTestEnvironment(tc.Client, true)
		Expect(err).NotTo(HaveOccurred())
	})

	AfterEach(func() {
		// Reset cleanupFuncs and testPods before next test
		CleanupAfterEach(tc.Client, tc.Clientset, tc.TestPods, tc.CleanupFuncs)
		tc.CleanupFuncs = nil
		tc.TestPods = []string{}
	})

	It("Verifies pod should egress traffic to perimeter cluster with multiple egress gateways", func() {
		sourcePodName := allowEgressPod
		perimeterVM1IP := "192.168.0.163"
		perimeterVM2IP := "192.168.0.164"
		var err error
		tc.TestPods, tc.CleanupFuncs, err = testEgressNATWithMultipleGateways(tc.Context, tc.Client, sourcePodName, perimeterVM, false, nil, EgressNATIPs, []string{perimeterVM1IP, perimeterVM2IP})
		Expect(err).NotTo(HaveOccurred(), fmt.Sprintf("pod %s is not able to connect to external IP via egress pod", sourcePodName))
	})

	It("Verifies VM should egress pod traffic to perimeter cluster with multiple egress gateways", func() {
		sourcePodVMName := allowEgressVM
		perimeterVM1IP := "192.168.0.165"
		perimeterVM2IP := "192.168.0.166"
		sourcePodVMIPs := []string{"192.168.0.2", "192.168.0.254"}
		var err error
		tc.TestPods, tc.CleanupFuncs, err = testEgressNATWithMultipleGateways(tc.Context, tc.Client, sourcePodVMName, perimeterVM, true, sourcePodVMIPs, EgressNATIPs, []string{perimeterVM1IP, perimeterVM2IP})
		Expect(err).NotTo(HaveOccurred(), fmt.Sprintf("vm %s is not able to connect to external IP via egress perimeter vm", sourcePodVMName))
	})
})

func testEgressNATWithMultipleGateways(ctx context.Context, cl k8sclient.Client, sourcePodName, perimeterVMName string, isEmulatedL3VMPod bool, sourcePodVMIPs, expectedNATIPs, perimeterVMIPs []string) ([]string, []func(), error) {
	var testPods []string
	var cleanupFuncs []func()
	var cleanupSourcePod func()
	var err error
	var sourcePodIP string

	sourcePodNames := []string{}
	sourcePodIPs := []string{}
	for i := 0; i < numSourcePods; i++ {
		var sourcePodIP string
		sourcePodName := fmt.Sprintf("%s--%d", sourcePodName, i)
		if isEmulatedL3VMPod {
			cleanupSourcePod, err = createEmulatedL3VMPod(ctx, cl, sourcePodName, gatewayNamespace, sourcePodVMIPs[i],
				utils.WithLabel(appSelectorLabelKey, appSelectorLabelValue), utils.WithLabel(allowEgressLabelKey, "false"))
			if err != nil {
				return testPods, cleanupFuncs, fmt.Errorf("failed to create vm pod %s : %v", sourcePodName, err)
			}
			sourcePodIP = sourcePodVMIPs[i]
		} else {
			cleanupSourcePod, err = utils.CreatePod(ctx, cl, sourcePodName, gatewayNamespace, utils.WithLabel(appSelectorLabelKey, appSelectorLabelValue), utils.WithLabel(allowEgressLabelKey, "false"))
			if err != nil {
				return testPods, cleanupFuncs, fmt.Errorf("failed to create pod %s : %v", sourcePodName, err)
			}
			sourcePodIP, err = utils.FetchPodIP(ctx, cl, sourcePodName, gatewayNamespace)
			if err != nil {
				return testPods, cleanupFuncs, fmt.Errorf("failed to fetch ip for pod %s: %v", sourcePodName, err)
			}
		}

		sourcePodNames = append(sourcePodNames, sourcePodName)
		testPods = append(testPods, sourcePodName)
		cleanupFuncs = append(cleanupFuncs, cleanupSourcePod)
		sourcePodIPs = append(sourcePodIPs, sourcePodIP)
	}

	cmds := []string{
		fmt.Sprintf("ip addr add %s/32 dev eth1; ", clusterExternalIP),
		fmt.Sprintf("ip route add %s/32 dev eth1 src %s; ", sourcePodIP, clusterExternalIP),
	}
	perimeterVMNames := []string{}
	for i, perimeterVMIP := range perimeterVMIPs {
		vmName := perimeterVMName + "--" + fmt.Sprintf("%d", i)
		perimeterVMNames = append(perimeterVMNames, vmName)
		opts := []utils.PodCustomization{
			utils.WithLabel("app", vmName),
			utils.WithResponderContainer(),
		}
		cleanupPerimeterVM, err := createEmulatedPerimeterVMPod(ctx, cl, vmName, gatewayNamespace, perimeterVMIP, cmds, opts...)
		if err != nil {
			return testPods, cleanupFuncs, fmt.Errorf("failed to create vm pod %s with affinity: %v", vmName, err)
		}
		testPods = append(testPods, vmName)
		cleanupFuncs = append(cleanupFuncs, cleanupPerimeterVM)

		for idx, sourcePodName := range sourcePodNames {
			// Verify Perimeter node VM basic connectivity with pod and vm
			klog.Infof("Running curl from source pod %s:%s directly to Perimeter VM %s:%s", sourcePodName, sourcePodIPs[idx], vmName, perimeterVMIP)
			err = utils.VerifyCurlFromPod(ctx, gatewayNamespace, sourcePodNames[0], perimeterVMIP, utils.ResponderPort, true, vmName)
			if err != nil {
				return testPods, cleanupFuncs, fmt.Errorf("pod %s is not able to connect to perimeter vm pod %s: %v", sourcePodName, vmName, err)
			}
		}
	}

	// Create CiliumEgressGatewayPolicy for egress NAT
	cleanupCiliumEgressGatewayPolicy, err := createCiliumEgressGatewayPolicy(ctx, cl, gatewayNamespace, expectedNATIPs, perimeterVMIPs, map[string]string{appSelectorLabelKey: appSelectorLabelValue})
	if err != nil {
		return testPods, cleanupFuncs, fmt.Errorf("failed to create ciliumegressgatewaypolicy with cloudNATIP %s and gatewayIP %s: %v", expectedNATIPs, perimeterVMIPs, err)
	}
	cleanupFuncs = append(cleanupFuncs, cleanupCiliumEgressGatewayPolicy)

	// To verify multigateway EgressNAT using a VM source Pod, we must ensure that requests originating
	// from different VMPods are distributed and routed out of separate gateway IPs.
	// We accomplish this by validating that each VM's source IP consistently maps to a distinct hash and, thus, a separate gateway.
	if isEmulatedL3VMPod {
		klog.Infof("Running curl from source pod %s:%s to external IP %s via pod %s:%s", sourcePodNames[0], sourcePodIPs[0], clusterExternalIP, perimeterVMNames, perimeterVMIPs[0])
		err = utils.VerifyCurlFromPod(ctx, gatewayNamespace, sourcePodNames[0], clusterExternalIP, utils.ResponderPort, true, perimeterVMNames[1])
		if err != nil {
			return testPods, cleanupFuncs, fmt.Errorf("pod %s is not able to connect to external IP via egress pod %s: %v", sourcePodName, perimeterVMNames, err)
		}

		klog.Infof("Running curl from source pod %s:%s to external IP %s via pod %s:%s", sourcePodNames[1], sourcePodIPs[1], clusterExternalIP, perimeterVMNames, perimeterVMIPs[0])
		err = utils.VerifyCurlFromPod(ctx, gatewayNamespace, sourcePodNames[1], clusterExternalIP, utils.ResponderPort, true, perimeterVMNames[0])
		if err != nil {
			return testPods, cleanupFuncs, fmt.Errorf("pod %s is not able to connect to external IP via egress pod %s: %v", sourcePodName, perimeterVMNames, err)
		}
	} else {
		for idx, sourcePodName := range sourcePodNames {
			// Verify Perimeter node VM basic connectivity with pod and vm
			klog.Infof("Running curl from source pod %s:%s to external IP %s via pod %s:%s", sourcePodName, sourcePodIPs[idx], clusterExternalIP, perimeterVMNames, perimeterVMIPs)
			err = utils.VerifyCurlFromPodWithMultipleOutputs(ctx, gatewayNamespace, sourcePodName, clusterExternalIP, utils.ResponderPort, true, perimeterVMNames)
			if err != nil {
				return testPods, cleanupFuncs, fmt.Errorf("pod %s is not able to connect to perimeter vm pod %s: %v", sourcePodName, perimeterVMName, err)
			}
		}
	}

	// Verify traffic not working after the label removed
	err = utils.RemovePodLabel(ctx, cl, k8sclient.ObjectKey{Name: sourcePodNames[0], Namespace: gatewayNamespace}, appSelectorLabelKey)
	if err != nil {
		return testPods, cleanupFuncs, fmt.Errorf("pod %s is not able to update label: %v", sourcePodName, err)
	}
	klog.Infof("Expected failed curl from allow egress pod %s:%s to external IP %s via pod %s:%s", sourcePodNames[0], sourcePodIPs[0], clusterExternalIP, perimeterVMNames, perimeterVMIPs)
	err = utils.VerifyCurlFromPod(ctx, gatewayNamespace, sourcePodNames[0], clusterExternalIP, utils.ResponderPort, false, "")
	if err != nil {
		return testPods, cleanupFuncs, fmt.Errorf("pod %s is able to connect to external IP via egress pod %s without egress label %s: %v", sourcePodName, perimeterVMName, allowEgressLabelKey, err)
	}
	// Verify traffic working again after the label added
	err = utils.AddPodLabel(ctx, cl, k8sclient.ObjectKey{Name: sourcePodNames[0], Namespace: gatewayNamespace}, map[string]string{appSelectorLabelKey: appSelectorLabelValue})
	if err != nil {
		return testPods, cleanupFuncs, fmt.Errorf("pod %s is not able to update label: %v", sourcePodName, err)
	}
	klog.Infof("Expected successful curl from allow egress pod %s:%s to external IP %s via pod %s:%s", sourcePodNames[0], sourcePodIPs[0], clusterExternalIP, perimeterVMNames, perimeterVMIPs)
	err = utils.VerifyCurlFromPodWithMultipleOutputs(ctx, gatewayNamespace, sourcePodNames[0], clusterExternalIP, utils.ResponderPort, true, perimeterVMNames)
	if err != nil {
		return testPods, cleanupFuncs, fmt.Errorf("pod %s is not able to connect to external IP via egress pod %s with re-added egress label: %v", sourcePodName, perimeterVMName, err)
	}
	return testPods, cleanupFuncs, nil
}
