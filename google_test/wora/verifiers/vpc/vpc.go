package vpc

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"time" // Do not use pkg/time in test code.

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	k8sclient "sigs.k8s.io/controller-runtime/pkg/client"

	klog "gke-internal.googlesource.com/syllogi/sanitized-klog/third_party/klogv2"
	e2escheme "gke-internal.googlesource.com/third_party/cilium/google_test/wora/e2e/pkg/test/scheme"
	"gke-internal.googlesource.com/third_party/cilium/google_test/wora/e2e/pkg/test/utils"
	"gke-internal.googlesource.com/third_party/cilium/google_test/wora/e2e/pkg/test/wait"
)

const (
	testNamespace = "vpc"
	tcpdumpPod    = "tcpdump"
	pcapFileDir   = "geneve.pcap"

	pod1Name = "pod1"
	pod2Name = "pod2"

	localPCAPPath = "/tmp/traffic.pcap"

	defaultVPCVNI = 0
)

var _ = Describe("Verifiers/VPC", Label("vpc"), Ordered, func() {
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

		ctx, _ = context.WithTimeout(context.Background(), 10*time.Minute)

		kubeconfig := os.Getenv("KUBECONFIG")

		config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
		Expect(err).NotTo(HaveOccurred())

		clientset, err = kubernetes.NewForConfig(config)
		Expect(err).NotTo(HaveOccurred(), "Failed to create Kubernetes clientset")

		cl, err = k8sclient.New(config, k8sclient.Options{Scheme: s})
		Expect(err).NotTo(HaveOccurred())
		enabled, err := isGoogleVPCEnabled(ctx, cl)
		Expect(err).NotTo(HaveOccurred(), "Failed to validate Google VPC configuration")

		if !enabled {
			klog.Infof("Skipping test because Google VPC is not enabled")
			Skip("Google VPC is disabled in this environment")
		}

		// Create the test namespace
		err = utils.CreateTestNamespace(ctx, cl, testNamespace)
		Expect(err).NotTo(HaveOccurred(), "Failed to create test namespace")
	})

	AfterAll(func() {
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

	It("Verifies cross nodes traffic is encapped with google geneve", func() {
		testPod1Name := pod1Name + "-diff-nodes"
		testPod2Name := pod2Name + "-diff-nodes"
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
		cleanup1, err := utils.CreatePod(ctx, cl, testPod1Name, testNamespace,
			utils.WithLabel("app", testPod1Name))
		Expect(err).NotTo(HaveOccurred())
		cleanupFuncs = append(cleanupFuncs, cleanup1)
		testPods = append(testPods, testPod1Name)

		cleanup2, err := utils.CreatePod(ctx, cl, testPod2Name, testNamespace,
			utils.WithLabel("app", testPod2Name),
			utils.WithAffinity(podAntiAffinity),
			utils.WithResponderContainer())
		Expect(err).NotTo(HaveOccurred())
		cleanupFuncs = append(cleanupFuncs, cleanup2)
		testPods = append(testPods, testPod2Name)

		pod1IP, err := utils.FetchPodIP(ctx, cl, testPod1Name, testNamespace)
		Expect(err).NotTo(HaveOccurred())

		pod2IP, err := utils.FetchPodIP(ctx, cl, testPod2Name, testNamespace)
		Expect(err).NotTo(HaveOccurred())

		cleanup3, err := createTCPDumpPod(ctx, cl, testPod2Name, testNamespace)
		Expect(err).NotTo(HaveOccurred())
		cleanupFuncs = append(cleanupFuncs, cleanup3)
		testPods = append(testPods, tcpdumpPod)

		Eventually(func() error {
			stopTCPDump, err := runTCPDump(tcpdumpPod, testNamespace, pcapFileDir)
			if err != nil {
				return err
			}
			// Make sure stopTCPDump is always called.
			defer stopTCPDump(tcpdumpPod, testNamespace)

			if err := utils.RunCurlFromPod(ctx, cl, testPod1Name, testPod2Name, pod2IP, utils.ResponderPort, testNamespace); err != nil {
				return err
			}

			// Add 5 seconds buffer for tcpdump to write pcap file.
			time.Sleep(5 * time.Second)
			if err := stopTCPDump(tcpdumpPod, testNamespace); err != nil {
				return err
			}

			if err := validateGeneveEncapped(tcpdumpPod, testNamespace, pcapFileDir, pod1IP, pod2IP); err != nil {
				return err
			}
			return nil
		}, 5*time.Minute, 10*time.Second).Should(Succeed(), "Unable to validate geneve packets")
	})
})

func copyPCAPFileToLocal(podName, namespace, remotePath, localPath string) error {
	cmd := exec.Command("kubectl", "cp", fmt.Sprintf("%s/%s:%s", namespace, podName, remotePath), localPath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to copy PCAP file: %v, output: %s", err, string(output))
	}
	return nil
}

// validateGeneveEncapped copies the pcap file from tcpdump pod and validate packets are encapped properly.
// The function validates both forward and reply packets are seen between the source and destination IP.
func validateGeneveEncapped(podName, namespace, remotePath, srcIP, dstIP string) error {
	if err := copyPCAPFileToLocal(podName, namespace, remotePath, localPCAPPath); err != nil {
		return err
	}

	handle, err := pcap.OpenOffline(localPCAPPath)
	if err != nil {
		return fmt.Errorf("failed to open PCAP file: %w", err)
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	var debugMessages []string
	var innerPacket gopacket.Packet
	forwardSeen := false
	replySeen := false
	src := net.ParseIP(srcIP)
	dst := net.ParseIP(dstIP)

	for packet := range packetSource.Packets() {
		debugMessages = append(debugMessages, packet.String())
		// Try to get the Geneve layer
		geneveLayer := packet.Layer(layers.LayerTypeGeneve)
		if geneveLayer == nil {
			continue
		}

		geneve, _ := geneveLayer.(*layers.Geneve)

		if geneve.VNI != defaultVPCVNI {
			continue
		}

		if geneve.Protocol != layers.EthernetTypeIPv4 {
			continue
		}

		// Extract the inner IPv4 packet from geneve payload.
		innerPacket = gopacket.NewPacket(geneve.LayerPayload(), layers.LayerTypeIPv4, gopacket.Default)
		innerIPv4Layer := innerPacket.Layer(layers.LayerTypeIPv4)
		if innerIPv4Layer == nil {
			continue
		}

		innerIP, _ := innerIPv4Layer.(*layers.IPv4)

		if innerIP.SrcIP.Equal(src) && innerIP.DstIP.Equal(dst) {
			if !forwardSeen {
				forwardSeen = true
				klog.Infof("Seen forward geneve encapped packet VNI=%d srcIP=%s dstIP=%s", geneve.VNI, innerIP.SrcIP, innerIP.DstIP)
			}
			if replySeen {
				return nil
			}
		}

		if innerIP.SrcIP.Equal(dst) && innerIP.DstIP.Equal(src) {
			if !replySeen {
				replySeen = true
				klog.Infof("Seen reply geneve encapped packet VNI=%d srcIP=%s dstIP=%s", geneve.VNI, innerIP.SrcIP, innerIP.DstIP)
			}
			if forwardSeen {
				return nil
			}
		}
	}

	// For debugging, print the entire capture if the test fails.
	return fmt.Errorf("failed to validate BPF geneve encapped packets with inner srcIP=%s dstIP= %s: Packets: %s",
		src.String(), dst.String(),
		strings.Join(debugMessages, "\n"),
	)
}

// createTCPDumpPod creates a host networking tcpdump pod scheduled on the same node as the provided pod.
func createTCPDumpPod(ctx context.Context, cl k8sclient.Client, withPod, ns string) (func(), error) {
	podAffinity := &corev1.Affinity{
		PodAffinity: &corev1.PodAffinity{
			RequiredDuringSchedulingIgnoredDuringExecution: []corev1.PodAffinityTerm{
				{
					LabelSelector: &metav1.LabelSelector{
						MatchLabels: map[string]string{
							"app": withPod,
						},
					},
					TopologyKey: "kubernetes.io/hostname",
				},
			},
		},
	}
	return utils.CreatePod(ctx, cl, tcpdumpPod, ns, utils.WithAffinity(podAffinity), utils.WithHostNetworking())
}

// runTCPDump executes a tcpdump command to capture geneve packets.
// The capture output is stored in a pcap file and will be analyzed in the following test.
// The function also returns a function to stop the tcpdump command before analyzing.
func runTCPDump(podName, ns, outputFile string) (func(podName, ns string) error, error) {
	cmd := exec.Command("kubectl",
		"exec",
		podName,
		"-n", ns,
		"--",
		"tcpdump",
		"-nei", "vxlan0", // Monitor on vxlan0 interface
		"-w", outputFile, // Write to the pcap file
	)

	klog.Infof("Starting TCPDump: %s", cmd.String())
	err := cmd.Start()
	if err != nil {
		return nil, fmt.Errorf("failed to execute curl command: %v", err)
	}

	stopTCPDumpFunc := func(podName, ns string) error {
		cmd := exec.Command("kubectl",
			"exec",
			podName,
			"-n", ns,
			"--",
			"pkill", "tcpdump")
		out, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("failed to stop tcpdump: %v; output=%s", err, out)
		}
		return nil
	}
	return stopTCPDumpFunc, nil
}

func isGoogleVPCEnabled(ctx context.Context, cl k8sclient.Client) (bool, error) {
	return utils.ValidateCiliumConfigFlag(ctx, cl, []utils.CiliumConfig{
		{
			Key:   "enable-google-bpf-geneve",
			Value: "true",
		},
		{
			Key:   "enable-google-vpc",
			Value: "true",
		},
	})
}
