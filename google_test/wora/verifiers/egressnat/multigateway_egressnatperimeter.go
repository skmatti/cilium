// GDC-ag egressnat test
// The test uses multi-networking pod with veth to simulate premier cluster.
// It similar the dataplane of Infra Cluster
package egressnat

import (
	"context"
	"fmt"
	"time" // Do not use pkg/time in test code.

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	k8sclient "sigs.k8s.io/controller-runtime/pkg/client"

	klog "gke-internal.googlesource.com/syllogi/sanitized-klog/third_party/klogv2"
	"gke-internal.googlesource.com/third_party/cilium/google_test/wora/e2e/pkg/test/utils"
)

var _ = Describe("Verifiers/EgressNATPerimeter", Label("multigateway_egressnatperimeter"), Ordered, func() {
	var tc TestContext

	BeforeAll(func() {
		var err error
		tc, err = InitTestContext(context.Background())
		Expect(err).NotTo(HaveOccurred(), "Failed to initialize test context")

		var ctx context.Context
		ctx, _ = context.WithTimeout(context.Background(), 20*time.Minute)
		tc.Context = ctx

		err = SetupTestEnvironment(tc.Context, tc.Client, false, &tc)
		Expect(err).NotTo(HaveOccurred(), "Failed to set up test environment")
	})

	AfterAll(func() {
		err := CleanupTestEnvironment(tc.Client, false)
		Expect(err).NotTo(HaveOccurred())
	})

	AfterEach(func() {
		klog.Infof("Deleting each test cases")
		CleanupAfterEach(tc.Client, tc.Clientset, tc.TestPods, tc.CleanupFuncs)
		tc.CleanupFuncs = nil
		tc.TestPods = []string{}
	})

	It("Verifies pods on worker node could egress with multiple egress gateways configured", func() {
		sourcePodName := allowEgressPod
		var err error
		tc.TestPods, tc.CleanupFuncs, err = testCloudNATFromPodPerimeterCluster(tc.Context, tc.Client, sourcePodName, tc.GatewayNodeNames, tc.GatewayNodeIPs, nil, EgressNATIPs, false)
		Expect(err).NotTo(HaveOccurred(), fmt.Sprintf("pod %s is not able to connect to bootstrapper", sourcePodName))
	})

	// TODO(b/466132572): Fix VM as source connectivitiy or remove VM as source logic in perimeter cluster in WORA test
	// It("Verifies VMs on worker node could egress with multiple egress gateways configured", func() {
	// 	sourcePodVMName := allowEgressVM
	// 	sourcePodVMIPs := []string{"192.168.0.1", "192.168.0.254"}
	// 	var err error
	// 	tc.TestPods, tc.CleanupFuncs, err = testCloudNATFromPodPerimeterCluster(tc.Context, tc.Client, sourcePodVMName, tc.GatewayNodeNames, tc.GatewayNodeIPs, sourcePodVMIPs, EgressNATIPs, true)
	// 	Expect(err).NotTo(HaveOccurred(), fmt.Sprintf("pod %s is not able to connect to bootstrapper", sourcePodVMName))
	// })
})

func testCloudNATFromPodPerimeterCluster(ctx context.Context, cl k8sclient.Client, sourcePodName string, gatewayNodeNames, gatewayNodeIPs, sourcePodVMIPs, expectedNATIPs []string, isEmulatedL3VMPod bool) ([]string, []func(), error) {
	var testPods []string
	var cleanupFuncs []func()

	sourcePodNames := []string{}
	sourcePodIPs := []string{}
	for i := 0; i < numSourcePods; i++ {
		var cleanupSourcePod func()
		var sourcePodIP string
		var err error

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

	cleanupCiliumEgressGatewayPolicy, err := createCiliumEgressGatewayPolicyPerimeterCluster(ctx, cl, gatewayNamespace, expectedNATIPs, gatewayNodeNames, nil, map[string]string{appSelectorLabelKey: appSelectorLabelValue})
	if err != nil {
		klog.Errorf("Failed to create cilium egress gateway policy: %v", err)
	}
	cleanupFuncs = append(cleanupFuncs, cleanupCiliumEgressGatewayPolicy)

	numGateways := min(len(expectedNATIPs), len(gatewayNodeNames))
	for i := 0; i < numGateways; i++ {
		// Need to add static route to return traffic from bootstrapper to node which replace the bgp setup in gdch
		cmd := fmt.Sprintf("ip route replace %s/32 via %s", expectedNATIPs[i], gatewayNodeIPs[i])
		output, err := utils.ExecuteCommandFromBootstapper(ctx, cl, cmd)
		if err != nil {
			return testPods, cleanupFuncs, fmt.Errorf("failed to execute command: %v at bootstrapper, output: %s, error: %v", cmd, output, err)
		}
	}

	// To verify multigateway EgressNAT using a VM source Pod, we must ensure that requests originating
	// from different VMPods are distributed and routed out of separate gateway IPs.
	// We accomplish this by validating that each VM's source IP consistently maps to a distinct hash and, thus, a separate gateway.
	if isEmulatedL3VMPod {
		klog.Infof("Running curl from allow egress pod %s to bootstrapper ip %s SNATed by %s", sourcePodNames[0], bootstrapperIP, expectedNATIPs[1])
		err = utils.VerifyCurlFromPod(ctx, gatewayNamespace, sourcePodNames[0], bootstrapperIP, utils.ResponderPort, true, expectedNATIPs[1])
		if err != nil {
			return testPods, cleanupFuncs, fmt.Errorf("pod %s is not able to connect to bootstrapper SNATed by %s: %v", sourcePodNames[0], expectedNATIPs[1], err)
		}

		klog.Infof("Running curl from allow egress pod %s to bootstrapper ip %s SNATed by %s", sourcePodNames[1], bootstrapperIP, expectedNATIPs[0])
		err = utils.VerifyCurlFromPod(ctx, gatewayNamespace, sourcePodNames[1], bootstrapperIP, utils.ResponderPort, true, expectedNATIPs[0])
		if err != nil {
			return testPods, cleanupFuncs, fmt.Errorf("pod %s is not able to connect to bootstrapper SNATed by %s: %v", sourcePodNames[1], expectedNATIPs[0], err)
		}
	} else {
		for _, sourcePodName := range sourcePodNames {
			// Verify Perimeter node VM basic connectivity with pod and vm
			klog.Infof("Running curl from allow egress pod %s to bootstrapper ip %s SNATed by %s", sourcePodName, bootstrapperIP, expectedNATIPs)
			err = utils.VerifyCurlFromPodWithMultipleOutputs(ctx, gatewayNamespace, sourcePodName, bootstrapperIP, utils.ResponderPort, true, expectedNATIPs)
			if err != nil {
				return testPods, cleanupFuncs, fmt.Errorf("pod %s is not able to connect to bootstrapper SNATed by %s: %v", sourcePodName, expectedNATIPs, err)
			}
		}
	}

	// Verify traffic not working after the label removed
	err = utils.RemovePodLabel(ctx, cl, k8sclient.ObjectKey{Name: sourcePodNames[0], Namespace: gatewayNamespace}, appSelectorLabelKey)
	if err != nil {
		return testPods, cleanupFuncs, fmt.Errorf("pod %s is not able to update label: %v", sourcePodName, err)
	}
	klog.Infof("Expected failed curl from allow egress pod %s to bootstrapper ip %s SNATed by %s", sourcePodName, bootstrapperIP, expectedNATIPs)
	err = utils.VerifyCurlFromPod(ctx, gatewayNamespace, sourcePodNames[0], bootstrapperIP, utils.ResponderPort, false, "")
	if err != nil {
		return testPods, cleanupFuncs, fmt.Errorf("pod %s is able to connect to bootstrapper without selector label %s: %v", sourcePodName, appSelectorLabelKey, err)
	}
	// Verify traffic working again after the label added
	err = utils.AddPodLabel(ctx, cl, k8sclient.ObjectKey{Name: sourcePodNames[0], Namespace: gatewayNamespace}, map[string]string{appSelectorLabelKey: appSelectorLabelValue})
	if err != nil {
		return testPods, cleanupFuncs, fmt.Errorf("pod %s is not able to update label: %v", sourcePodName, err)
	}
	klog.Infof("Running curl from allow egress pod %s to bootstrapper ip %s SNATed by %s", sourcePodName, bootstrapperIP, expectedNATIPs)
	err = utils.VerifyCurlFromPodWithMultipleOutputs(ctx, gatewayNamespace, sourcePodNames[0], bootstrapperIP, utils.ResponderPort, true, expectedNATIPs)
	if err != nil {
		return testPods, cleanupFuncs, fmt.Errorf("pod %s is not able to connect to bootstrapper SNATed by %s: %v", sourcePodName, expectedNATIPs, err)
	}

	return testPods, cleanupFuncs, nil
}
