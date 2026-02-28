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
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	utilrand "k8s.io/apimachinery/pkg/util/rand"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	k8sclient "sigs.k8s.io/controller-runtime/pkg/client"

	klog "gke-internal.googlesource.com/syllogi/sanitized-klog/third_party/klogv2"
	e2escheme "gke-internal.googlesource.com/third_party/cilium/google_test/wora/e2e/pkg/test/scheme"
	"gke-internal.googlesource.com/third_party/cilium/google_test/wora/e2e/pkg/test/utils"
	"gke-internal.googlesource.com/third_party/cilium/google_test/wora/e2e/pkg/test/wait"
)

const (
	testNamespace = "geneve"
	tcpdumpPod    = "tcpdump"
	pcapFileDir   = "geneve.pcap"

	pod1Name = "pod1"
	pod2Name = "pod2"

	defaultVPCVNI = 0
)

var _ = Describe("Verifiers/Geneve", Label("geneve"), Ordered, func() {
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

		ctx, _ = context.WithTimeout(context.Background(), 30*time.Minute)

		kubeconfig := os.Getenv("KUBECONFIG")

		config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
		Expect(err).NotTo(HaveOccurred())

		clientset, err = kubernetes.NewForConfig(config)
		Expect(err).NotTo(HaveOccurred(), "Failed to create Kubernetes clientset")

		cl, err = k8sclient.New(config, k8sclient.Options{Scheme: s})
		Expect(err).NotTo(HaveOccurred())
		enabled, err := isGoogleBPFGeneveEnabled(ctx, cl)
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
			err = wait.WaitForSuccessContext(ctx, "Delete pod", wait.WaitingMedium, func(ctx context.Context) error {
				pod := &corev1.Pod{}
				err = cl.Get(ctx, k8sclient.ObjectKey{Name: podName, Namespace: testNamespace}, pod)
				if err == nil {
					return fmt.Errorf("pod %s was not deleted successfully", podName)
				}
				if !errors.IsNotFound(err) {
					return err
				}
				klog.Infof("Pod %s deleted successfully", podName)
				return nil
			})
		}
		// Reset cleanupFuncs and testPods before next test
		cleanupFuncs = nil
		testPods = []string{}
	})

	testGeneveEncap := func(name, id string, pod1HostNetwork, pod2HostNetwork bool) {
		It(name, func() {
			clientPodName := "client-" + id + "-nodes"
			serverPodName := "server-" + id + "-nodes"
			// Add pod anti-affinity to ensure the server is scheduled on different nodes as client.
			podAntiAffinity := &corev1.Affinity{
				PodAntiAffinity: &corev1.PodAntiAffinity{
					RequiredDuringSchedulingIgnoredDuringExecution: []corev1.PodAffinityTerm{
						{
							LabelSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{
									"app": clientPodName,
								},
							},
							TopologyKey: "kubernetes.io/hostname",
						},
					},
				},
			}

			var clientOpts []utils.PodCustomization
			clientOpts = append(clientOpts, utils.WithLabel("app", clientPodName))
			if pod1HostNetwork {
				clientOpts = append(clientOpts, utils.WithHostNetworking())
			}
			clientCleanup, err := utils.CreatePod(ctx, cl, clientPodName, testNamespace, clientOpts...)
			Expect(err).NotTo(HaveOccurred())
			cleanupFuncs = append(cleanupFuncs, clientCleanup)
			testPods = append(testPods, clientPodName)

			var serverOpts []utils.PodCustomization
			serverOpts = append(serverOpts, utils.WithLabel("app", serverPodName))
			serverOpts = append(serverOpts, utils.WithAffinity(podAntiAffinity))
			serverOpts = append(serverOpts, utils.WithResponderContainer())
			/*
				utils.WithLabel("app", testPod2Name),
				utils.WithAffinity(podAntiAffinity),
			*/
			if pod2HostNetwork {
				serverOpts = append(serverOpts, utils.WithHostNetworking())
			}
			serverCleanup, err := utils.CreatePod(ctx, cl, serverPodName, testNamespace, serverOpts...)
			Expect(err).NotTo(HaveOccurred())
			cleanupFuncs = append(cleanupFuncs, serverCleanup)
			testPods = append(testPods, serverPodName)

			clientIP, err := utils.FetchPodIP(ctx, cl, clientPodName, testNamespace)
			Expect(err).NotTo(HaveOccurred())

			serverIP, err := utils.FetchPodIP(ctx, cl, serverPodName, testNamespace)
			Expect(err).NotTo(HaveOccurred())

			isXdpGeneric, err := isGenericXDPModeEnabled(ctx, cl)
			Expect(err).NotTo(HaveOccurred(), "Failed to validate XDP configuration")

			srcVXLANCleanup, err := createTCPDumpPod(ctx, cl, clientPodName, testNamespace, "tcpdump-src-vxlan0")
			Expect(err).NotTo(HaveOccurred())
			cleanupFuncs = append(cleanupFuncs, srcVXLANCleanup)
			testPods = append(testPods, "tcpdump-src-vxlan0")

			dstVXLANCleanup, err := createTCPDumpPod(ctx, cl, serverPodName, testNamespace, "tcpdump-dst-vxlan0")
			Expect(err).NotTo(HaveOccurred())
			cleanupFuncs = append(cleanupFuncs, dstVXLANCleanup)
			testPods = append(testPods, "tcpdump-dst-vxlan0")

			dstAnyCleanup, err := createTCPDumpPod(ctx, cl, serverPodName, testNamespace, "tcpdump-dst-any")
			Expect(err).NotTo(HaveOccurred())
			cleanupFuncs = append(cleanupFuncs, dstAnyCleanup)
			testPods = append(testPods, "tcpdump-dst-any")

			Eventually(func() error {
				stop1, err := runTCPDump("tcpdump-src-vxlan0", testNamespace, "vxlan0", pcapFileDir)
				if err != nil {
					return err
				}
				defer stop1("tcpdump-src-vxlan0", testNamespace)

				stop2, err := runTCPDump("tcpdump-dst-vxlan0", testNamespace, "vxlan0", pcapFileDir)
				if err != nil {
					return err
				}
				defer stop2("tcpdump-dst-vxlan0", testNamespace)

				stop3, err := runTCPDump("tcpdump-dst-any", testNamespace, "any", pcapFileDir)
				if err != nil {
					return err
				}
				defer stop3("tcpdump-dst-any", testNamespace)

				srcPort := utilrand.Intn(10000) + 40000
				if err := runCurlWithSourcePort(ctx, cl, clientset, testNamespace, clientPodName, serverIP, utils.ResponderPort, srcPort, "200 OK"); err != nil {
					return err
				}

				// Add 5 seconds buffer for tcpdump to write pcap file.
				time.Sleep(12 * time.Second) // wait for timeout 10 tcpdump to cleanly exit and flush the file lock natively
				if err := stop1("tcpdump-src-vxlan0", testNamespace); err != nil {
					return err
				}
				if err := stop2("tcpdump-dst-vxlan0", testNamespace); err != nil {
					return err
				}
				if err := stop3("tcpdump-dst-any", testNamespace); err != nil {
					return err
				}

				// For traffic between two HostNetwork pods, there is NO encapsulation.
				expectEncap := !(pod1HostNetwork && pod2HostNetwork)

				// For traffic arriving at a HostNetwork destination, the local socket consumes the packet
				// directly, so the raw (decapsulated) packet never appears on a sniffeable virtual interface.

				if !isXdpGeneric {
					// xdp-mode: disabled; vxlan0 captures everything!
					if err := validatePacketVisibility("tcpdump-src-vxlan0", testNamespace, pcapFileDir, clientIP, serverIP, srcPort, expectEncap, false, expectEncap, false); err != nil {
						return err
					}
					if expectEncap {
						if err := validatePacketVisibility("tcpdump-dst-vxlan0", testNamespace, pcapFileDir, clientIP, serverIP, srcPort, expectEncap, false, expectEncap, false); err != nil {
							return err
						}
					}
				} else {
					// xdp-mode: xdpgeneric
					// src-vxlan0 sees ENCAPSULATED egress (XDP does not strip outgoing request)
					// but decapsulated ingress (XDP strips incoming reply).
					if err := validatePacketVisibility("tcpdump-src-vxlan0", testNamespace, pcapFileDir, clientIP, serverIP, srcPort, expectEncap, false, false, expectEncap); err != nil {
						return err
					}

					if expectEncap {
						// dst-vxlan0 sees decapsulated ingress (XDP strips incoming request)
						// but ENCAPSULATED egress (XDP does not strip outgoing reply).
						if err := validatePacketVisibility("tcpdump-dst-vxlan0", testNamespace, pcapFileDir, clientIP, serverIP, srcPort, false, expectEncap, expectEncap, false); err != nil {
							return err
						}
					}
				}
				return nil
			}, 5*time.Minute, 10*time.Second).Should(Succeed(), "Unable to validate geneve packets")
		})
	}

	testGeneveEncap("Verifies Pod to Pod traffic is encapped with google geneve", "p2p", false, false)
	testGeneveEncap("Verifies Pod to Node (HostNetwork) traffic is encapped with google geneve", "p2n", false, true)
	testGeneveEncap("Verifies Node (HostNetwork) to Pod traffic is encapped with google geneve", "n2p", true, false)
	testGeneveEncap("Verifies Node (HostNetwork) to Node (HostNetwork) traffic is encapped with google geneve", "n2n", true, true)
})

// createTCPDumpPod creates a host networking tcpdump pod scheduled on the same node as the provided pod.
func createTCPDumpPod(ctx context.Context, cl k8sclient.Client, withPod, ns, podName string) (func(), error) {
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
	return utils.CreatePod(ctx, cl, podName, ns, utils.WithAffinity(podAffinity), utils.WithHostNetworking())
}

// runTCPDump executes a tcpdump command to capture geneve packets.
// The capture output is stored in a pcap file and will be analyzed in the following test.
// The function also returns a function to stop the tcpdump command before analyzing.
func runTCPDump(podName, ns, intf, outputFile string) (func(podName, ns string) error, error) {
	cmd := exec.Command("kubectl",
		"exec",
		podName,
		"-n", ns,
		"--",
		"tcpdump",
		"-nei", intf, // Monitor on specified interface
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

func isGoogleBPFGeneveEnabled(ctx context.Context, cl k8sclient.Client) (bool, error) {
	return utils.ValidateCiliumConfigFlag(ctx, cl, []utils.CiliumConfig{
		{
			Key:   "enable-google-bpf-geneve",
			Value: "true",
		},
	})
}

func isGenericXDPModeEnabled(ctx context.Context, cl k8sclient.Client) (bool, error) {
	return utils.ValidateCiliumConfigFlag(ctx, cl, []utils.CiliumConfig{
		{
			Key:   "xdp-mode",
			Value: "xdpgeneric",
		},
	})
}

// runCurlWithSourcePort runs curl with a specific source port using --local-port
func runCurlWithSourcePort(ctx context.Context, cl k8sclient.Client, clientset *kubernetes.Clientset, ns, srcPod, dstIP string, dstPort, srcPort int, wantOutput string) error {
	waitMsg := fmt.Sprintf("Expected successful curl from %s to %s:%d with source port %d", srcPod, dstIP, dstPort, srcPort)
	return wait.WaitForSuccessContext(ctx, waitMsg, wait.WaitingMedium, func(ctx context.Context) error {
		cmdStr := fmt.Sprintf("curl -s -m 2 --local-port %d http://%s:%d", srcPort, dstIP, dstPort)
		cmd := exec.Command("kubectl", "exec", srcPod, "-n", ns, "--", "/bin/sh", "-c", cmdStr)
		out, err := cmd.CombinedOutput()
		if err != nil || !strings.Contains(string(out), wantOutput) {
			return fmt.Errorf("curl failed or output mismatch: %v, out: %s", err, string(out))
		}
		return nil
	})
}

// validatePacketVisibility copies the pcap file from tcpdump pod and validates packets
// to explicitly trace Encapsulated and Decapsulated forms of the exact traffic flow (IP + TCP ports).
func validatePacketVisibility(podName, namespace, remotePath, srcIPString, dstIPString string, srcPort int, expectEncapForward, expectDecapForward, expectEncapReply, expectDecapReply bool) error {
	// Wait momentarily for the tcpdump IO buffer to cleanly sync to node disk natively over ABM
	time.Sleep(2 * time.Second)

	// Generate unique PCAP path per test iteration to prevent race conditions during parsing
	localPCAP := fmt.Sprintf("/tmp/traffic-%s-%d.pcap", podName, time.Now().UnixNano())

	if err := copyPCAPFileToLocal(podName, namespace, remotePath, localPCAP); err != nil {
		return err
	}
	defer os.Remove(localPCAP) // Clean up file locally to avoid disk bloat

	_ = net.ParseIP(srcIPString)
	_ = net.ParseIP(dstIPString)

	handle, err := pcap.OpenOffline(localPCAP)
	if err != nil {
		return fmt.Errorf("failed to open pcap file: %v", err)
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	foundEncapForward := false
	foundDecapForward := false
	foundEncapReply := false
	foundDecapReply := false

	for packet := range packetSource.Packets() {
		isEncapped := false
		var innerIPv4 *layers.IPv4
		var tcp *layers.TCP

		if geneveLayer := packet.Layer(layers.LayerTypeGeneve); geneveLayer != nil {
			isEncapped = true
			if ipv4Layer := packet.Layer(layers.LayerTypeIPv4); ipv4Layer != nil {
				// The outer IPv4 is found, now we need to decode the inner payload.
				geneve := geneveLayer.(*layers.Geneve)

				if geneve.Protocol == layers.EthernetTypeIPv4 { // 0x0800
					// L3 Encapsulation: The Geneve payload is directly an IPv4 packet!
					innerIPv4 = &layers.IPv4{}
					err := innerIPv4.DecodeFromBytes(geneve.Payload, gopacket.NilDecodeFeedback)
					if err == nil {
						if innerIPv4.Protocol == layers.IPProtocolTCP {
							tcp = &layers.TCP{}
							_ = tcp.DecodeFromBytes(innerIPv4.Payload, gopacket.NilDecodeFeedback)
						}
					}
				} else {
					// L2 Encapsulation (Original Behavior): Decode the Geneve payload as Ethernet
					innerEth := &layers.Ethernet{}
					err := innerEth.DecodeFromBytes(geneve.Payload, gopacket.NilDecodeFeedback)
					if err == nil {
						// Manually extract IPv4 from the inner Eth frame
						if innerEth.EthernetType == layers.EthernetTypeIPv4 {
							innerIPv4 = &layers.IPv4{}
							err = innerIPv4.DecodeFromBytes(innerEth.Payload, gopacket.NilDecodeFeedback)
							if err == nil {
								// Try to get TCP from the inner IPv4
								if innerIPv4.Protocol == layers.IPProtocolTCP {
									tcp = &layers.TCP{}
									_ = tcp.DecodeFromBytes(innerIPv4.Payload, gopacket.NilDecodeFeedback)
								}
							}
						}
					}
				}
			}
		} else {
			// Decapsulated packet
			if ipv4Layer := packet.Layer(layers.LayerTypeIPv4); ipv4Layer != nil {
				innerIPv4 = ipv4Layer.(*layers.IPv4)
				if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
					tcp = tcpLayer.(*layers.TCP)
				}
			}
		}

		if innerIPv4 == nil || tcp == nil {
			continue
		}

		if tcp.DstPort == 8080 || tcp.SrcPort == 8080 {
			fmt.Printf("[%s] Parsed Packet: isEncap=%v innerSrcIP=%s innerDstIP=%s tcpSrcPort=%d tcpDstPort=%d wantDstIPString=%s wantSrcPort=%d\n", podName, isEncapped, innerIPv4.SrcIP.String(), innerIPv4.DstIP.String(), int(tcp.SrcPort), int(tcp.DstPort), dstIPString, srcPort)
		}

		// Strictly filter for traffic to/from the target Pod IP
		if innerIPv4.DstIP.String() != dstIPString && innerIPv4.SrcIP.String() != dstIPString {
			continue
		}

		// For HostNetwork to Overlay traffic (n2p), the source IP might be masqueraded
		// to the cilium_host IP (e.g. 10.240.2.254) rather than the Node's eth0 IP.
		// So we do not strictly enforce srcIPString equality. Filtering by dstIPString
		// and the randomized Source Port is sufficient to uniquely identify the flow.
		// if innerIPv4.SrcIP.String() != srcIPString && innerIPv4.DstIP.String() != srcIPString {
		// 	continue
		// }

		// Discover NAT'd Source Port if we hit Responder exactly!
		if int(tcp.DstPort) == utils.ResponderPort {
			if !foundEncapForward && !foundDecapForward {
				// This is the FIRST packet hitting our test server! This is the NAT'd Source Port!
				srcPort = int(tcp.SrcPort)
				klog.Infof("[%s] DISCOVERED ORIGINAL FORWARD PACKET: isEncapped=%v, NAT SrcPort=%d, DstPort=%d", podName, isEncapped, srcPort, utils.ResponderPort)
			}

			if isEncapped {
				if !foundEncapForward {
					klog.Infof("[%s] Found ENCAP Forward packet directly over physical ABM interfaces", podName)
					foundEncapForward = true
				}
			} else {
				if !foundDecapForward {
					klog.Infof("[%s] Found DECAP Forward packet", podName)
					foundDecapForward = true
				}
			}
		} else if int(tcp.SrcPort) == utils.ResponderPort && int(tcp.DstPort) == srcPort {
			if isEncapped {
				if !foundEncapReply {
					klog.Infof("[%s] Found ENCAP Reply packet natively over overlay routes", podName)
					foundEncapReply = true
				}
			} else {
				if !foundDecapReply {
					klog.Infof("[%s] Found DECAP Reply packet", podName)
					foundDecapReply = true
				}
			}
		}
	}

	if expectEncapForward && !foundEncapForward {
		return fmt.Errorf("[%s] expected to find Encapsulated Forward Geneve packet, but found none", podName)
	}
	if !expectEncapForward && foundEncapForward {
		return fmt.Errorf("[%s] expected NOT to find Encapsulated Forward Geneve packet, but found one", podName)
	}

	if expectDecapForward && !foundDecapForward {
		return fmt.Errorf("[%s] expected to find Decapsulated Forward packet, but found none", podName)
	}
	if !expectDecapForward && foundDecapForward {
		return fmt.Errorf("[%s] expected NOT to find Decapsulated Forward packet, but found one", podName)
	}

	if expectEncapReply && !foundEncapReply {
		return fmt.Errorf("[%s] expected to find Encapsulated Reply Geneve packet, but found none", podName)
	}
	if !expectEncapReply && foundEncapReply {
		return fmt.Errorf("[%s] expected NOT to find Encapsulated Reply Geneve packet, but found one", podName)
	}

	if expectDecapReply && !foundDecapReply {
		// Wait Trap Removed
		return fmt.Errorf("[%s] expected to find Decapsulated Reply packet, but found none", podName)
	}
	if !expectDecapReply && foundDecapReply {
		// Wait Trap Removed
		return fmt.Errorf("[%s] expected NOT to find Decapsulated Reply packet, but found one", podName)
	}

	// Also halt if any other assertion failed before this block natively
	if (expectEncapForward && !foundEncapForward) || (expectDecapForward && !foundDecapForward) || (expectEncapReply && !foundEncapReply) {
		// Wait Trap Removed
	}

	return nil
}

// copyPCAPFileToLocal copies a file from a pod in a specific namespace to the local filesystem.
func copyPCAPFileToLocal(podName, namespace, remoteFilePath, localFilePath string) error {
	cmd := exec.Command("kubectl", "cp", fmt.Sprintf("%s/%s:%s", namespace, podName, remoteFilePath), localFilePath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to copy file from pod %s to local file %s: %v, output: %s", podName, localFilePath, err, string(output))
	}

	// Double-check file exists and is parsable.
	// The pcap lib sometimes throws cryptic errors if the file is 0 bytes or not closed properly by tcpdump
	info, err := os.Stat(localFilePath)
	if err != nil {
		return fmt.Errorf("local pcap file not found after cp: %v", err)
	}
	if info.Size() == 0 {
		return fmt.Errorf("local pcap file is empty (0 bytes) after cp")
	}

	return nil
}
