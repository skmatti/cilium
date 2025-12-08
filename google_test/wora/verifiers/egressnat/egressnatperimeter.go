// GDC-ag egressnat test
// The test uses multi-networking pod with veth to simulate premier cluster.
// It simiular the dataplane of Infra Cluster
package egressnat

import (
	"context"
	"fmt"
	"math"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time" // Do not use pkg/time in test code.

	ciliumv2metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/selection"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	k8sclient "sigs.k8s.io/controller-runtime/pkg/client"

	klog "gke-internal.googlesource.com/syllogi/sanitized-klog/third_party/klogv2"
	e2escheme "gke-internal.googlesource.com/third_party/cilium/google_test/wora/e2e/pkg/test/scheme"
	"gke-internal.googlesource.com/third_party/cilium/google_test/wora/e2e/pkg/test/utils"
	"gke-internal.googlesource.com/third_party/cilium/google_test/wora/e2e/pkg/test/wait"
	ciliumv2 "gke-internal.googlesource.com/third_party/cilium/pkg/k8s/apis/cilium.io/v2"
)

const (
	workerNodeLabel                = "node-role.kubernetes.io/worker="
	bootstrapperIP                 = "10.200.0.1"
	TimeoutRegularAnyAnnotation    = "egress.networking.gke.io/TimeoutRegularAnyAnnotation"
	TimeoutRegularTcpAnnotation    = "egress.networking.gke.io/TimeoutRegularTcpAnnotation"
	TimeoutRegularTcpFinAnnotation = "egress.networking.gke.io/TimeoutRegularTcpFinAnnotation"
	TimeoutRegularTcpSynAnnotation = "egress.networking.gke.io/TimeoutRegularTcpSynAnnotation"
)

var (
	egressTimeoutAnnotations = map[string]string{
		TimeoutRegularAnyAnnotation:    "100",
		TimeoutRegularTcpAnnotation:    "200",
		TimeoutRegularTcpFinAnnotation: "300",
		TimeoutRegularTcpSynAnnotation: "400",
	}

	egressTimeouts = map[string]int64{
		TimeoutRegularAnyAnnotation:    100,
		TimeoutRegularTcpAnnotation:    200,
		TimeoutRegularTcpFinAnnotation: 300,
		TimeoutRegularTcpSynAnnotation: 400,
	}
)

var _ = Describe("Verifiers/EgressNATPerimeter", Label("egressnatperimeter"), Ordered, func() {
	var (
		cl             k8sclient.Client
		err            error
		testPods       []string
		cleanupFuncs   []func()
		ctx            context.Context
		clientset      *kubernetes.Clientset
		egressNodeName string
		egressNodeIP   string
	)

	BeforeAll(func() {
		s := e2escheme.SchemeV2()

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
		// Get target egressNAT node
		workerNodes, err := utils.GetNodeListByLabel(ctx, cl, workerNodeLabel)
		if err != nil && len(workerNodes.Items) == 0 {
			klog.Errorf("Failed to get worker node for cluster %s: %v", cl.Scheme().Name(), err)
		}
		egressNodeName = workerNodes.Items[0].Name
		if workerNodes.Items[0].Status.Addresses == nil {
			klog.Errorf("Failed to get worker node address for node %s: %v", egressNodeName, err)
		}
		egressNodeIP = workerNodes.Items[0].Status.Addresses[0].Address
	})

	AfterAll(func() {
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
		klog.Infof("Deleting each test cases")
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
			err = wait.WaitForSuccessContext(ctx, "Delete pod", wait.WaitingMedium, func(ctx context.Context) error {
				pod := &corev1.Pod{}
				err = cl.Get(ctx, k8sclient.ObjectKey{Name: podName, Namespace: testNamespace}, pod)
				if err == nil {
					return fmt.Errorf("pod %s was not deleted successfully", podName)
				}
				klog.Infof("Pod %s deleted successfully", podName)
				return nil
			})
		}
		// Reset cleanupFuncs and testPods before next test
		cleanupFuncs = nil
		testPods = []string{}
	})

	It("Verifies pods on worker node could egress through same node", func() {
		allowEgressPodName := allowEgressPod + "--same-node"
		podAffinity := &corev1.Affinity{
			NodeAffinity: &corev1.NodeAffinity{
				RequiredDuringSchedulingIgnoredDuringExecution: &corev1.NodeSelector{
					NodeSelectorTerms: []corev1.NodeSelectorTerm{
						{
							MatchExpressions: []corev1.NodeSelectorRequirement{
								{
									Key:      "metadata.name",
									Operator: corev1.NodeSelectorOpIn,
									Values:   []string{egressNodeName},
								},
							},
						},
					},
				},
			},
		}
		// Verify allowEgressPod can do egress NAT to reach bootstrapper by SNAT
		testPods, cleanupFuncs, err = testEgressNATFromPodPerimeterCluster(ctx, cl, allowEgressPodName, egressNodeName, egressNodeIP, podAffinity)
		Expect(err).NotTo(HaveOccurred(), fmt.Sprintf("pod %s is not able to connect to bootstrapper", allowEgressPodName))
		// TODO(b/449220402): re-enable when the flakiness is fixed.
		// err = testEgressConnectionTimeouts(ctx, cl, allowEgressPodName, egressNodeName, TimeoutRegularTcpFinAnnotation)
		// Expect(err).NotTo(HaveOccurred(), fmt.Sprintf("pod %s connection timeouts are incorrect via egress perimeter vm %s", allowEgressPodName, egressNodeName))
	})

	It("Verifies pods on worker node could egress through different node", func() {
		allowEgressPodName := allowEgressPod + "--diff-node"
		podAntiAffinity := &corev1.Affinity{
			NodeAffinity: &corev1.NodeAffinity{
				RequiredDuringSchedulingIgnoredDuringExecution: &corev1.NodeSelector{
					NodeSelectorTerms: []corev1.NodeSelectorTerm{
						{
							MatchExpressions: []corev1.NodeSelectorRequirement{
								{
									Key:      "metadata.name",
									Operator: corev1.NodeSelectorOpNotIn,
									Values:   []string{egressNodeName},
								},
							},
						},
					},
				},
			},
		}
		// Verify allowEgressPod can do egress NAT to reach bootstrapper by SNAT
		testPods, cleanupFuncs, err = testEgressNATFromPodPerimeterCluster(ctx, cl, allowEgressPodName, egressNodeName, egressNodeIP, podAntiAffinity)
		Expect(err).NotTo(HaveOccurred(), fmt.Sprintf("pod %s is not able to connect to bootstrapper", allowEgressPodName))
		// TODO(b/449220402): re-enable when the flakiness is fixed.
		// Verify custom egress timeouts are applied for traffic from remote src endpoints
		// err = testEgressConnectionTimeouts(ctx, cl, allowEgressPodName, egressNodeName, TimeoutRegularTcpFinAnnotation)
		// Expect(err).NotTo(HaveOccurred(), fmt.Sprintf("pod %s connection timeouts are incorrect via egress perimeter vm %s", allowEgressPodName, egressNodeName))
	})

})

func testEgressNATFromPodPerimeterCluster(ctx context.Context, cl k8sclient.Client, allowEgressPodName, egressNodeName, egressNodeIP string, affinity *corev1.Affinity) ([]string, []func(), error) {
	var testPods []string
	var cleanupFuncs []func()
	cleanupCiliumEgressGatewayPolicy, err := createCiliumEgressGatewayPolicyPerimeterCluster(ctx, cl, testNamespace, []string{egressNATIP}, []string{egressNodeName}, egressTimeoutAnnotations, map[string]string{"egress.networking.gke.io/enabled": "true"})
	if err != nil {
		klog.Errorf("Failed to create cilium egress gateway policy: %v", err)
	}
	cleanupFuncs = append(cleanupFuncs, cleanupCiliumEgressGatewayPolicy)
	cleanupAlowEgressPod, err := utils.CreatePod(ctx, cl, allowEgressPodName, testNamespace,
		utils.WithLabel("app", allowEgressPodName), utils.WithLabel(allowEgressLabelKey, "true"))
	if err != nil {
		return testPods, cleanupFuncs, fmt.Errorf("failed to create pod %s : %v", allowEgressPodName, err)
	}
	testPods = append(testPods, allowEgressPodName)
	cleanupFuncs = append(cleanupFuncs, cleanupAlowEgressPod)
	// Need to add static route to return traffic from bootstrapper to node which replace the bgp setup in gdch
	cmd := fmt.Sprintf("ip route replace %s/32 via %s", egressNATIP, egressNodeIP)
	output, err := utils.ExecuteCommandFromBootstapper(ctx, cl, cmd)
	if err != nil {
		return testPods, cleanupFuncs, fmt.Errorf("failed to execute command: %v at bootstrapper, output: %s, error: %v", cmd, output, err)
	}
	// Verify EgressNAT traffic
	klog.Infof("Running curl from allow egress pod %s to bootstrapper ip %s SNATed by %s", allowEgressPodName, bootstrapperIP, egressNATIP)
	err = utils.VerifyCurlFromPod(ctx, testNamespace, allowEgressPodName, bootstrapperIP, utils.ResponderPort, true, egressNATIP)
	if err != nil {
		return testPods, cleanupFuncs, fmt.Errorf("pod %s is not able to connect to bootstrapper SNATed by %s: %v", allowEgressPodName, egressNATIP, err)
	}
	// Verify traffic not working after the label removed
	err = removePodEgressLabel(ctx, cl, allowEgressPodName)
	if err != nil {
		return testPods, cleanupFuncs, fmt.Errorf("pod %s is not able to update label: %v", allowEgressPodName, err)
	}
	klog.Infof("Expected failed curl from allow egress pod %s to bootstrapper ip %s SNATed by %s", allowEgressPodName, bootstrapperIP, egressNATIP)
	err = utils.VerifyCurlFromPod(ctx, testNamespace, allowEgressPodName, bootstrapperIP, utils.ResponderPort, false, "")
	if err != nil {
		return testPods, cleanupFuncs, fmt.Errorf("pod %s is able to connect to bootstrapper without egress label %s: %v", allowEgressPodName, allowEgressLabelKey, err)
	}
	// Verify traffic working again after the label added
	err = addPodEgressLabel(ctx, cl, allowEgressPodName)
	if err != nil {
		return testPods, cleanupFuncs, fmt.Errorf("pod %s is not able to update label: %v", allowEgressPodName, err)
	}
	klog.Infof("Running curl from allow egress pod %s to bootstrapper ip %s SNATed by %s", allowEgressPodName, bootstrapperIP, egressNATIP)
	err = utils.VerifyCurlFromPod(ctx, testNamespace, allowEgressPodName, bootstrapperIP, utils.ResponderPort, true, egressNATIP)
	if err != nil {
		return testPods, cleanupFuncs, fmt.Errorf("pod %s is not able to connect to bootstrapper SNATed by %s: %v", allowEgressPodName, egressNATIP, err)
	}

	return testPods, cleanupFuncs, nil
}

func testEgressConnectionTimeouts(ctx context.Context, cl k8sclient.Client, allowEgressPodName, perimeterNodeName, timeoutsAnnotation string) error {
	anetdLabel, err := labels.NewRequirement(
		"k8s-app",
		selection.Equals,
		[]string{string("cilium")},
	)
	if err != nil {
		return err
	}

	listOptions := k8sclient.ListOptions{
		LabelSelector: labels.NewSelector().Add(*anetdLabel),
		FieldSelector: fields.SelectorFromSet(fields.Set{"spec.nodeName": perimeterNodeName}),
	}

	anetdPods := &corev1.PodList{}
	err = cl.List(ctx, anetdPods, &listOptions)

	if anetdPods.Items == nil || len(anetdPods.Items) == 0 {
		return fmt.Errorf("no anetd pods found")
	}

	anetdPod := anetdPods.Items[0]
	klog.Infof("Got Anetd Pod: %s, %s", anetdPod.Name, anetdPod.Namespace)

	if err != nil {
		panic(err.Error())
	}

	srcPod := &corev1.Pod{}
	err = cl.Get(ctx, k8sclient.ObjectKey{Name: allowEgressPodName, Namespace: testNamespace}, srcPod)
	if err != nil {
		klog.Errorf("Failed to get scrPod %s: %v", allowEgressPodName, err)
		return err
	}

	srcPodIP := srcPod.Status.PodIP
	anetdCommand := "cilium bpf ct list global | grep " + srcPodIP + " | grep TCP"
	cmd := exec.Command(
		"kubectl", "exec", anetdPod.Name, "-n", anetdPod.Namespace, "--", "bash", "-c",
		anetdCommand,
	)
	klog.Infof("Running command: %s", cmd.String())

	output, err := cmd.CombinedOutput()
	if err != nil {
		klog.Errorf("Failed to execute ct lookup command: %v", err)
		return err
	}

	differences, err := ParseCtOutput(output)

	// Conntrack lifetimes are stored in jiffies, which are equal to 0.256 seconds.
	// Set the error threshold to 5% to account for small flucuations in setting timeouts.
	for _, diff := range differences {
		threshold := float64(egressTimeouts[timeoutsAnnotation]) * 0.05
		absoluteDiff := math.Abs(float64(diff)*0.256 - float64(egressTimeouts[timeoutsAnnotation]))

		if absoluteDiff > threshold {
			return fmt.Errorf("got timeout: %d, expected: %d, difference exceeds 5%%", diff, egressTimeouts[timeoutsAnnotation])
		}
	}
	return nil
}

func createCiliumEgressGatewayPolicyPerimeterCluster(ctx context.Context, cl k8sclient.Client, name string, expectedNATIPs []string, hostNames []string, annotations map[string]string, podSelectorLabels map[string]string) (func(), error) {
	cleanup := func() {
		// Delete CiliumEgressGatewayPolicy
		err := cl.Delete(ctx, &ciliumv2.CiliumEgressGatewayPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name: name,
			},
		})
		if err != nil {
			klog.Warningf("Failed to delete CiliumEgressGatewayPolicy %s: %v", name, err)
		} else {
			klog.Infof("Deleting CiliumEgressGatewayPolicy %s", name)
		}
	}

	expectedNATIPs = expectedNATIPs[:min(len(expectedNATIPs), len(hostNames))]
	if len(expectedNATIPs) == 0 {
		return func() {}, fmt.Errorf("failed to create CiliumEgressGatewayPolicy %s: expectedNATIPs or hostnames list cannot be empty", name)
	}

	cegp := &ciliumv2.CiliumEgressGatewayPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:        name,
			Annotations: annotations,
		},
		Spec: ciliumv2.CiliumEgressGatewayPolicySpec{
			DestinationCIDRs: []ciliumv2.IPv4CIDR{
				"0.0.0.0/0",
			},
			Selectors: []ciliumv2.EgressRule{
				{
					NamespaceSelector: &v1.LabelSelector{
						MatchLabels: map[string]string{
							"kubernetes.io/metadata.name": name,
						},
					},
					PodSelector: &v1.LabelSelector{
						MatchLabels: podSelectorLabels,
					},
				},
			},
		},
	}

	gateways := []ciliumv2.EgressGateway{}
	for i, expectedNATIP := range expectedNATIPs {
		gateway := ciliumv2.EgressGateway{
			EgressIP: expectedNATIP,
			NodeSelector: &ciliumv2metav1.LabelSelector{
				MatchLabels: map[string]string{
					HostnameLabel: hostNames[i],
				},
			},
		}
		gateways = append(gateways, gateway)
	}

	if len(expectedNATIPs) == 1 {
		cegp.Spec.EgressGateway = &gateways[0]
	} else {
		cegp.ObjectMeta.Labels = map[string]string{
			"networking.gdc.goog/cloud-nat-gateway-name":      gatewayName,
			"networking.gdc.goog/cloud-nat-gateway-namespace": gatewayNamespace,
		}
		cegp.Spec.EgressGateways = gateways
		// EgressGateway is ignored when egressGateways is present.
		// For multi-gateway configurations it is set here only to satisfy CEL validation rules.
		cegp.Spec.EgressGateway = &ciliumv2.EgressGateway{
			EgressIP: invalidEgressIP,
			NodeSelector: &ciliumv2metav1.LabelSelector{
				MatchLabels: map[string]string{
					HostnameLabel: "invalid-hostname",
				},
			},
		}
	}

	if err := cl.Create(ctx, cegp); err != nil {
		return cleanup, fmt.Errorf("failed to create CiliumEgressGatewayPolicy %s: %w", name, err)
	}

	return cleanup, nil
}

func ParseCtOutput(output []byte) ([]int64, error) {
	outputStr := string(output)
	lines := strings.Split(outputStr, "\n")
	var differences []int64

	for _, line := range lines {
		if strings.Contains(line, "expires=") && strings.Contains(line, "LastRxReport=") {
			parts := strings.Split(line, " ")
			var expires, lastRxReport int64
			for _, part := range parts {
				if strings.HasPrefix(part, "expires=") {
					valStr := strings.TrimPrefix(part, "expires=")
					val, err := strconv.ParseInt(valStr, 10, 64)
					if err != nil {
						return nil, fmt.Errorf("error parsing expires: %w", err)
					}
					expires = val
				}
				if strings.HasPrefix(part, "LastRxReport=") {
					valStr := strings.TrimPrefix(part, "LastRxReport=")
					val, err := strconv.ParseInt(valStr, 10, 64)
					if err != nil {
						return nil, fmt.Errorf("error parsing LastRxReport: %w", err)
					}
					lastRxReport = val
				}
			}
			differences = append(differences, expires-lastRxReport)
		}
	}
	return differences, nil
}
