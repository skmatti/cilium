// GDC-ag egressnat test
// The test uses multi-networking pod with veth to simulate premier cluster.
// It simiular the dataplane of Infra Cluster
package egressnat

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time" // Do not use pkg/time in test code.

	ciliumv2metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	ciliumv2 "gke-internal.googlesource.com/third_party/cilium/pkg/k8s/apis/cilium.io/v2"
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
	allowEgressPod       = "allow-egress-pod"
	allowEgressVM        = "allow-egress-vm"
	testNamespace        = "egressnat"
	perimeterVM          = "perimeter-vm"
	perimeterNetworkName = "g-org-1-perimeter-cluster"
	defaultNetworkName   = "g-default-vpc"
	egressNATIP          = "10.200.32.15"
	clusterExternalIP    = "10.248.0.1"
	allowEgressLabelKey  = "egress.networking.gke.io/enabled"
	HostnameLabel        = "kubernetes.io/hostname"
	invalidHostName      = "invalid-hostname"
	invalidEgressIP      = "10.200.32.12"
)

var _ = Describe("Verifiers/EgressNAT", Label("egressnat"), Ordered, func() {
	var (
		cl           k8sclient.Client
		err          error
		testPods     []string
		cleanupFuncs []func()
		ctx          context.Context
		clientset    *kubernetes.Clientset
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

		ipamMode := networkv1.ExternalMode
		gateway := "192.168.0.1"
		nodeIntf := "vxlan0"
		l3PerimeterNetwork := networkv1.Network{
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
		err = cl.Create(ctx, &l3PerimeterNetwork)
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
		err = cl.Create(context.TODO(), &l3DefaultNetwork)
		if err != nil && !apierrors.IsAlreadyExists(err) {
			Expect(err).NotTo(HaveOccurred(), "Failed to create l3 network")
		}
	})

	AfterAll(func() {
		klog.Infof("Deleting l3 perimeter network %s", perimeterNetworkName)
		network := &networkv1.Network{
			ObjectMeta: metav1.ObjectMeta{
				Name: perimeterNetworkName,
			},
		}
		err := utils.DeleteAndWait(ctx, cl, network)
		Expect(err).NotTo(HaveOccurred())

		klog.Infof("Deleting l3 default network %s", defaultNetworkName)
		network = &networkv1.Network{
			ObjectMeta: metav1.ObjectMeta{
				Name: defaultNetworkName,
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

	It("Verifies pod should egress traffic to perimeter cluster on different nodes", func() {
		allowEgressPodName := allowEgressPod + "--diff-node"
		perimeterVMName := perimeterVM + "--diff-node"
		perimeterVMIP := "192.168.0.150"
		allowEgressVMIP := "" // Not used for pod
		// Add anti-affinity to ensure the Perimeter VM Pod is not scheduled on the same node as the allowEgress Pod
		podAntiAffinity := &corev1.Affinity{
			PodAntiAffinity: &corev1.PodAntiAffinity{
				RequiredDuringSchedulingIgnoredDuringExecution: []corev1.PodAffinityTerm{
					{
						LabelSelector: &metav1.LabelSelector{
							MatchLabels: map[string]string{
								"app": allowEgressPodName,
							},
						},
						TopologyKey: HostnameLabel,
					},
				},
			},
		}
		// Verify allowEgressPod can do egress NAT from perimeterVM
		testPods, cleanupFuncs, err = testEgressNATFromPod(ctx, cl, allowEgressPodName, perimeterVMName, podAntiAffinity, false, perimeterVMIP, allowEgressVMIP)
		Expect(err).NotTo(HaveOccurred(), fmt.Sprintf("pod %s is not able to connect to external IP via egress pod %s", allowEgressPodName, perimeterVMName))
	})

	It("Verifies pod should egress traffic to perimeter cluster on same node", func() {
		allowEgressPodName := allowEgressPod + "--same-node"
		perimeterVMName := perimeterVM + "--same-node"
		perimeterVMIP := "192.168.0.151"
		allowEgressVMIP := "" // Not used for pod
		// Add affinity to ensure the Perimeter VM Pod is scheduled on the same node as the allowEgress Pod
		podAffinity := &corev1.Affinity{
			PodAffinity: &corev1.PodAffinity{
				RequiredDuringSchedulingIgnoredDuringExecution: []corev1.PodAffinityTerm{
					{
						LabelSelector: &metav1.LabelSelector{
							MatchLabels: map[string]string{
								"app": allowEgressPodName,
							},
						},
						TopologyKey: HostnameLabel,
					},
				},
			},
		}
		// Verify allowEgressPod can do egress NAT from perimeterVM
		testPods, cleanupFuncs, err = testEgressNATFromPod(ctx, cl, allowEgressPodName, perimeterVMName, podAffinity, false, perimeterVMIP, allowEgressVMIP)
		Expect(err).NotTo(HaveOccurred(), fmt.Sprintf("pod %s is not able to connect to external IP via egress pod %s", allowEgressPodName, perimeterVMName))
	})

	It("Verifies VM should egress traffic to perimeter cluster on different nodes", func() {
		allowEgressVMName := allowEgressVM + "--diff-node"
		perimeterVMName := perimeterVM + "--diff-node"
		perimeterVMIP := "192.168.0.152"
		allowEgressVMIP := "192.168.0.153"
		// Add anti-affinity to ensure the Perimeter VM Pod is not scheduled on the same node as the allowEgress Pod
		podAntiAffinity := &corev1.Affinity{
			PodAntiAffinity: &corev1.PodAntiAffinity{
				RequiredDuringSchedulingIgnoredDuringExecution: []corev1.PodAffinityTerm{
					{
						LabelSelector: &metav1.LabelSelector{
							MatchLabels: map[string]string{
								"app": allowEgressVMName,
							},
						},
						TopologyKey: HostnameLabel,
					},
				},
			},
		}
		// Verify allowEgressPod can do egress NAT from perimeterVM
		testPods, cleanupFuncs, err = testEgressNATFromPod(ctx, cl, allowEgressVMName, perimeterVMName, podAntiAffinity, true, perimeterVMIP, allowEgressVMIP)
		Expect(err).NotTo(HaveOccurred(), fmt.Sprintf("vm %s is not able to connect to external IP via egress perimeter vm %s", allowEgressVMName, perimeterVMName))
	})

	It("Verifies VM should egress pod traffic to perimeter cluster on same node", func() {
		allowEgressVMName := allowEgressVM + "--same-node"
		perimeterVMName := perimeterVM + "--same-node"
		perimeterVMIP := "192.168.0.154"
		allowEgressVMIP := "192.168.0.155"
		// Add affinity to ensure the Perimeter VM Pod is scheduled on the same node as the allowEgress Pod
		podAffinity := &corev1.Affinity{
			PodAffinity: &corev1.PodAffinity{
				RequiredDuringSchedulingIgnoredDuringExecution: []corev1.PodAffinityTerm{
					{
						LabelSelector: &metav1.LabelSelector{
							MatchLabels: map[string]string{
								"app": allowEgressVMName,
							},
						},
						TopologyKey: HostnameLabel,
					},
				},
			},
		}
		// Verify allowEgressPod can do egress NAT from perimeterVM
		testPods, cleanupFuncs, err = testEgressNATFromPod(ctx, cl, allowEgressVMName, perimeterVMName, podAffinity, true, perimeterVMIP, allowEgressVMIP)
		Expect(err).NotTo(HaveOccurred(), fmt.Sprintf("vm %s is not able to connect to external IP via egress perimeter vm %s", allowEgressVMName, perimeterVMName))
	})
})

func testEgressNATFromPod(ctx context.Context, cl k8sclient.Client, allowEgressPodName, perimeterVMName string, affinity *corev1.Affinity, isEmulatedL3VMPod bool, perimeterVMIP, allowEgressVMIP string) ([]string, []func(), error) {
	var testPods []string
	var cleanupFuncs []func()
	var cleanupAllowEgressPod func()
	var err error
	var allowEgressIP string

	if isEmulatedL3VMPod {
		cleanupAllowEgressPod, err = createEmulatedL3VMPod(ctx, cl, allowEgressPodName, testNamespace, allowEgressVMIP,
			utils.WithLabel("app", allowEgressPodName), utils.WithLabel(allowEgressLabelKey, "true"))
		if err != nil {
			return testPods, cleanupFuncs, fmt.Errorf("failed to create vm pod %s : %v", allowEgressPodName, err)
		}
	} else {
		cleanupAllowEgressPod, err = utils.CreatePod(ctx, cl, allowEgressPodName, testNamespace,
			utils.WithLabel("app", allowEgressPodName), utils.WithLabel(allowEgressLabelKey, "true"))
		if err != nil {
			return testPods, cleanupFuncs, fmt.Errorf("failed to create pod %s : %v", allowEgressPodName, err)
		}
	}
	testPods = append(testPods, allowEgressPodName)
	cleanupFuncs = append(cleanupFuncs, cleanupAllowEgressPod)
	if isEmulatedL3VMPod {
		allowEgressIP = allowEgressVMIP
	} else {
		allowEgressIP, err = utils.FetchPodIP(ctx, cl, allowEgressPodName, testNamespace)
		if err != nil {
			return testPods, cleanupFuncs, fmt.Errorf("failed to fetch ip for pod %s: %v", allowEgressPodName, err)
		}
	}
	cmds := []string{
		fmt.Sprintf("ip addr add %s/32 dev eth1; ", clusterExternalIP),
		fmt.Sprintf("ip route add %s/32 dev eth1 src %s; ", allowEgressIP, clusterExternalIP),
	}
	cleanup, err := createEmulatedPerimeterVMPod(ctx, cl, perimeterVMName, testNamespace, perimeterVMIP, cmds, utils.WithLabel("app", perimeterVMName), utils.WithAffinity(affinity), utils.WithResponderContainer())
	if err != nil {
		return testPods, cleanupFuncs, fmt.Errorf("failed to create vm pod %s with affinity: %v", perimeterVMName, err)
	}
	testPods = append(testPods, perimeterVMName)
	cleanupFuncs = append(cleanupFuncs, cleanup)
	// Verify Perimeter VM basic connectivity with pod and vm
	klog.Infof("Running curl from allow egress pod %s:%s directly to Perimeter VM %s:%s", allowEgressPodName, allowEgressIP, perimeterVMName, perimeterVMIP)
	err = utils.VerifyCurlFromPod(ctx, testNamespace, allowEgressPodName, perimeterVMIP, utils.ResponderPort, true, perimeterVMName)
	if err != nil {
		return testPods, cleanupFuncs, fmt.Errorf("pod %s is not able to connect to perimeter vm pod %s: %v", allowEgressPodName, perimeterVMName, err)
	}

	// Create CiliumEgressGatewayPolicy for egress NAT
	cleanupCiliumEgressGatewayPolicy, err := createCiliumEgressGatewayPolicy(ctx, cl, testNamespace, []string{egressNATIP}, []string{perimeterVMIP}, map[string]string{"egress.networking.gke.io/enabled": "true"})
	if err != nil {
		return testPods, cleanupFuncs, fmt.Errorf("failed to create ciliumegressgatewaypolicy with egressNATIP %s and gatewayIP %s: %v", egressNATIP, perimeterVMIP, err)
	}
	cleanupFuncs = append(cleanupFuncs, cleanupCiliumEgressGatewayPolicy)

	// Verify EgressNAT traffic
	klog.Infof("Running curl from allow egress pod %s:%s to external IP %s via pod %s:%s", allowEgressPodName, allowEgressIP, clusterExternalIP, perimeterVMName, perimeterVMIP)
	err = utils.VerifyCurlFromPod(ctx, testNamespace, allowEgressPodName, clusterExternalIP, utils.ResponderPort, true, perimeterVMName)
	if err != nil {
		return testPods, cleanupFuncs, fmt.Errorf("pod %s is not able to connect to external IP via egress pod %s: %v", allowEgressPodName, perimeterVMName, err)
	}
	// Verify traffic not working after the label removed
	err = removePodEgressLabel(ctx, cl, allowEgressPodName)
	if err != nil {
		return testPods, cleanupFuncs, fmt.Errorf("pod %s is not able to update label: %v", allowEgressPodName, err)
	}
	klog.Infof("Expected failed curl from allow egress pod %s:%s to external IP %s via pod %s:%s", allowEgressPodName, allowEgressIP, clusterExternalIP, perimeterVMName, perimeterVMIP)
	err = utils.VerifyCurlFromPod(ctx, testNamespace, allowEgressPodName, clusterExternalIP, utils.ResponderPort, false, "")
	if err != nil {
		return testPods, cleanupFuncs, fmt.Errorf("pod %s is able to connect to external IP via egress pod %s without egress label %s: %v", allowEgressPodName, perimeterVMName, allowEgressLabelKey, err)
	}
	// Verify traffic working again after the label added
	err = addPodEgressLabel(ctx, cl, allowEgressPodName)
	if err != nil {
		return testPods, cleanupFuncs, fmt.Errorf("pod %s is not able to update label: %v", allowEgressPodName, err)
	}
	klog.Infof("Expected successful curl from allow egress pod %s:%s to external IP %s via pod %s:%s", allowEgressPodName, allowEgressIP, clusterExternalIP, perimeterVMName, perimeterVMIP)
	err = utils.VerifyCurlFromPod(ctx, testNamespace, allowEgressPodName, clusterExternalIP, utils.ResponderPort, true, perimeterVMName)
	if err != nil {
		return testPods, cleanupFuncs, fmt.Errorf("pod %s is not able to connect to external IP via egress pod %s with re-added egress label: %v", allowEgressPodName, perimeterVMName, err)
	}
	return testPods, cleanupFuncs, nil
}

// createEmulatedPerimeterMPod creates a pod with two interfaces (eth0 and eth1).
func createEmulatedPerimeterVMPod(ctx context.Context, cl k8sclient.Client, podName, ns, ip string, cmds []string, opts ...utils.PodCustomization) (func(), error) {
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

func removePodEgressLabel(ctx context.Context, cl k8sclient.Client, podName string) error {
	pod := &corev1.Pod{}
	err := cl.Get(ctx, k8sclient.ObjectKey{Name: podName, Namespace: testNamespace}, pod)
	if err != nil {
		return fmt.Errorf("failed to get pod %s: %v", podName, err)
	}
	delete(pod.Labels, allowEgressLabelKey)
	err = cl.Update(ctx, pod)
	if err != nil {
		return fmt.Errorf("failed to remove label for pod %s: %v", podName, err)
	}
	return nil
}

func addPodEgressLabel(ctx context.Context, cl k8sclient.Client, podName string) error {
	pod := &corev1.Pod{}
	err := cl.Get(ctx, k8sclient.ObjectKey{Name: podName, Namespace: testNamespace}, pod)
	if err != nil {
		return fmt.Errorf("failed to get pod %s", podName)
	}
	if pod.Labels == nil {
		pod.Labels = make(map[string]string)
	}
	pod.Labels[allowEgressLabelKey] = "true"
	err = cl.Update(ctx, pod)
	if err != nil {
		return fmt.Errorf("failed to add label for pod %s", podName)
	}
	return nil
}

func createCiliumEgressGatewayPolicy(ctx context.Context, cl k8sclient.Client, namespace string, expectedNATIPs, gatewayIPs []string, podSelectorLabels map[string]string) (func(), error) {
	policyName := namespace

	cleanup := func() {
		// Delete CiliumEgressGatewayPolicy
		err := cl.Delete(ctx, &ciliumv2.CiliumEgressGatewayPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name: policyName,
			},
		})
		if err != nil {
			klog.Warningf("Failed to delete CiliumEgressGatewayPolicy %s: %v", policyName, err)
		} else {
			klog.Infof("Deleting CiliumEgressGatewayPolicy %s", policyName)
		}
	}

	if len(expectedNATIPs) == 0 {
		return func() {}, fmt.Errorf("failed to create CiliumEgressGatewayPolicy %s: expectedNATIPs list cannot be empty", policyName)
	}
	if len(expectedNATIPs) != len(gatewayIPs) {
		return cleanup, fmt.Errorf("the number of expectedNATIPs (%d) must match the number of gatewayIPs (%d)", len(expectedNATIPs), len(gatewayIPs))
	}

	cegp := &ciliumv2.CiliumEgressGatewayPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:        policyName,
			Annotations: make(map[string]string),
			Labels:      make(map[string]string),
		},
		Spec: ciliumv2.CiliumEgressGatewayPolicySpec{
			Selectors: []ciliumv2.EgressRule{
				{
					NamespaceSelector: &v1.LabelSelector{
						MatchLabels: map[string]string{
							"kubernetes.io/metadata.name": namespace,
						},
					},
					PodSelector: &v1.LabelSelector{
						MatchLabels: podSelectorLabels,
					},
				},
			},
			DestinationCIDRs: []ciliumv2.IPv4CIDR{
				"0.0.0.0/0",
			},
		},
	}

	egressGateways := []ciliumv2.EgressGateway{}
	for _, expectedNATIP := range expectedNATIPs {
		egressGateways = append(egressGateways, ciliumv2.EgressGateway{
			EgressIP: expectedNATIP,
			NodeSelector: &ciliumv2metav1.LabelSelector{
				MatchLabels: map[string]string{
					HostnameLabel: invalidHostName,
				},
			},
		})
	}

	if len(egressGateways) == 1 {
		cegp.ObjectMeta.Annotations["networking.gke.io/gateway-ip"] = gatewayIPs[0]
		cegp.Spec.EgressGateway = &egressGateways[0]
	} else {
		type CloudNatGateway struct {
			EgressIP  string `json:"egressIP"`
			GatewayIP string `json:"gatewayIP"`
		}
		var annotationGateways []CloudNatGateway
		for i, gatewayIP := range gatewayIPs {
			annotationGateways = append(annotationGateways, CloudNatGateway{
				EgressIP:  expectedNATIPs[i],
				GatewayIP: gatewayIP,
			})
		}
		annotationJsonBytes, err := json.Marshal(annotationGateways)
		if err != nil {
			return cleanup, fmt.Errorf("failed to marshal cloud nat gateways to JSON: %w", err)
		}
		cegp.ObjectMeta.Annotations["networking.gke.io/cloud-nat-gateways"] = string(annotationJsonBytes)

		cegp.ObjectMeta.Labels = map[string]string{
			"networking.gdc.goog/cloud-nat-gateway-name":      gatewayName,
			"networking.gdc.goog/cloud-nat-gateway-namespace": gatewayNamespace,
		}
		cegp.Spec.EgressGateways = egressGateways
		// EgressGateway is ignored when egressGateways is present.
		// For multi-gateway configurations it is set here only to satisfy CEL validation rules.
		cegp.Spec.EgressGateway = &ciliumv2.EgressGateway{
			EgressIP: invalidEgressIP,
			NodeSelector: &ciliumv2metav1.LabelSelector{
				MatchLabels: map[string]string{
					HostnameLabel: invalidHostName,
				},
			},
		}
	}
	if err := cl.Create(ctx, cegp); err != nil {
		return cleanup, fmt.Errorf("failed to create CiliumEgressGatewayPolicy: %v", err)
	}
	return cleanup, nil
}
