package loadbalancer

import (
	"context"
	"fmt"
	"log"
	"os"
	"strings"
	"time" // Do not use pkg/time in test code.

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	k8sclient "sigs.k8s.io/controller-runtime/pkg/client"

	"gke-internal.googlesource.com/third_party/cilium/google_test/wora/e2e/pkg/test/wait"

	klog "gke-internal.googlesource.com/syllogi/sanitized-klog/third_party/klogv2"
	"gke-internal.googlesource.com/third_party/cilium/google_test/wora/e2e/pkg/test/common"
	e2eflags "gke-internal.googlesource.com/third_party/cilium/google_test/wora/e2e/pkg/test/flags"
	e2escheme "gke-internal.googlesource.com/third_party/cilium/google_test/wora/e2e/pkg/test/scheme"
	"gke-internal.googlesource.com/third_party/cilium/google_test/wora/e2e/pkg/test/utils"
)

var (
	ctx          context.Context
	clientset    *kubernetes.Clientset
	cl           k8sclient.Client
	cleanupFuncs []func()
	testPods     []string
	clusterType  common.ClusterType
)

const (
	testNamespace  = "loadbalancer"
	serviceName    = "lbservice1"
	pod1Name       = "lbservicetestpod1"
	pod2Name       = "lbservicetestpod2"
	servicePort    = 80
	nodeIntf       = "vxlan0"
	tcpdumpTimeout = 20
	pcapFileDir    = "response.pcap"
	localPCAPPath  = "/tmp/response.pcap"
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
		// Get the cluster type
		clusterType, err = e2eflags.ClusterType()
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
		backendIPs, err := createBackends(false)
		Expect(err).ToNot(HaveOccurred())
		err = testLoadBalancerService(backendIPs)
		Expect(err).ToNot(HaveOccurred())
	})

	It("Verifies IPv4 LoadBalancer connectivity from bootstrap with hostNetwork Backend and anti-affinity", func() {
		backendIPs, err := createBackends(true)
		Expect(err).ToNot(HaveOccurred())
		err = testLoadBalancerService(backendIPs)
		Expect(err).ToNot(HaveOccurred())
	})

})

// testLoadBalanceService function
//   - validate NodePort is working correctly for all the nodes.
//   - ensure that lbservice is ready.
//   - run curl command from bootstrapper and ensure everything is in order.
func testLoadBalancerService(backendIPs []string) error {
	// skip verify the nodeport when backend will do SNAT when at the same node under Perimeter Cluster
	// rev_nat happens which using ct doing SNAT
	if clusterType != common.ClusterTypePerimeter {
		err := verifyNodePort(backendIPs)
		if err != nil {
			return err
		}
	}
	err := utils.WaitForServiceReadiness(ctx, cl, serviceName, testNamespace, corev1.ServiceTypeLoadBalancer)
	if err != nil {
		return err
	}

	service := corev1.Service{}
	err = cl.Get(ctx, k8sclient.ObjectKey{Name: serviceName, Namespace: testNamespace}, &service)
	if err != nil {
		return err
	}

	for _, ingress := range service.Status.LoadBalancer.Ingress {
		if clusterType == common.ClusterTypePerimeter {
			err := verifyConnectionPerimeterClusterFromBootstrapper(ctx, cl, ingress.IP, servicePort, backendIPs)
			if err != nil {
				return err
			}
		} else {
			err := utils.RunCurlFromBootstrapper(ctx, cl, ingress.IP, servicePort, wait.WaitingMedium)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

// verifyNodePort verifies the working of nodeport at each node.
func verifyNodePort(backendIPs []string) error {
	// Get nodes in the cluster.
	nodes, err := clientset.CoreV1().Nodes().List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		return err
	}
	if len(nodes.Items) == 0 {
		return fmt.Errorf("node list should not be empty")
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
		// For perimeter cluster
		if clusterType == common.ClusterTypePerimeter {
			err := verifyConnectionPerimeterClusterFromBootstrapper(ctx, cl, nodeip, nodeport, backendIPs)
			if err != nil {
				return err
			}
		} else {
			err := utils.RunCurlFromBootstrapper(ctx, cl, nodeip, nodeport, wait.WaitingMedium)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func createBackends(hostNetworkBackend bool) ([]string, error) {
	backendIPs := []string{}
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
	if hostNetworkBackend {
		cleanup1, err := utils.CreatePod(ctx, cl, pod1Name, testNamespace,
			utils.WithLabel("app", serviceName),
			utils.WithResponderContainer(),
			utils.WithAffinity(affinity),
			utils.WithHostNetworking())
		if err != nil {
			return nil, err
		}
		testPods = append(testPods, pod1Name)
		cleanupFuncs = append(cleanupFuncs, cleanup1)
		pod1IP, err := utils.FetchPodIP(ctx, cl, pod1Name, testNamespace)
		if err != nil {
			return nil, err
		}
		backendIPs = append(backendIPs, pod1IP)

		cleanup2, err := utils.CreatePod(ctx, cl, pod2Name, testNamespace,
			utils.WithLabel("app", serviceName),
			utils.WithResponderContainer(),
			utils.WithAffinity(affinity),
			utils.WithHostNetworking())
		if err != nil {
			return nil, err
		}
		testPods = append(testPods, pod2Name)
		cleanupFuncs = append(cleanupFuncs, cleanup2)
		pod2IP, err := utils.FetchPodIP(ctx, cl, pod2Name, testNamespace)
		if err != nil {
			return nil, err
		}
		backendIPs = append(backendIPs, pod2IP)

	} else {
		cleanup1, err := utils.CreatePod(ctx, cl, pod1Name, testNamespace,
			utils.WithLabel("app", serviceName),
			utils.WithResponderContainer(),
			utils.WithAffinity(affinity))
		if err != nil {
			return nil, err
		}
		pod1IP, err := utils.FetchPodIP(ctx, cl, pod1Name, testNamespace)
		if err != nil {
			return nil, err
		}
		backendIPs = append(backendIPs, pod1IP)
		testPods = append(testPods, pod1Name)
		cleanupFuncs = append(cleanupFuncs, cleanup1)

		cleanup2, err := utils.CreatePod(ctx, cl, pod2Name, testNamespace,
			utils.WithLabel("app", serviceName),
			utils.WithResponderContainer(),
			utils.WithAffinity(affinity))
		if err != nil {
			return nil, err
		}
		pod2IP, err := utils.FetchPodIP(ctx, cl, pod2Name, testNamespace)
		if err != nil {
			return nil, err
		}
		backendIPs = append(backendIPs, pod2IP)
		testPods = append(testPods, pod2Name)
		cleanupFuncs = append(cleanupFuncs, cleanup2)
	}
	return backendIPs, nil
}

// Use tcpdump to verify the return packet without SNAT return back to server
// Perimeter cluster didn't do SNAT, so the src ip will be backend ip.
func verifyConnectionPerimeterClusterFromBootstrapper(ctx context.Context, cl k8sclient.Client, targetIP string, port int32, backendIPs []string) error {
	var filterParts []string
	if len(backendIPs) > 0 {
		var ipFilters []string
		for _, ip := range backendIPs {
			if ip != "" {
				ipFilters = append(ipFilters, fmt.Sprintf("src host %s", ip))
			}
		}
		filterParts = append(filterParts, "("+strings.Join(ipFilters, " or ")+")")
	}
	filterParts = append(filterParts, fmt.Sprintf("src port %d", utils.ResponderPort))
	filterString := strings.Join(filterParts, " and ")

	tcpdumpCmd := fmt.Sprintf("sudo timeout %ds tcpdump -i %s -n -U -w %s '%s'",
		tcpdumpTimeout,
		nodeIntf,
		pcapFileDir,
		filterString, // filterString can be empty if no IPs/port specified
	)
	klog.Infof("running tcpdump command: %s on bootstrapper", tcpdumpCmd)
	// Run non-blocking tcpdump to get the packets
	closeConnectionFunc, client, session, err := utils.ExecuteNonBlockingCommandFromBootstapper(ctx, cl, tcpdumpCmd)
	if err != nil {

		return fmt.Errorf("failed to execute non-blocking command: %v at bootstrapper, error: %v", tcpdumpCmd, err)
	}
	// Make sure close connection is always called.
	defer closeConnectionFunc(client, session)
	curlCommand := fmt.Sprintf("curl -m %d -s S http://%s:%d", tcpdumpTimeout, targetIP, port)
	output, err := utils.ExecuteCommandFromBootstapper(ctx, cl, curlCommand)
	if err == nil {
		klog.Infof("Running command: %s with output: %s", curlCommand, output)
		return fmt.Errorf("expect curl fail with unable to connect, output:%s, error: %v", output, err)
	}
	klog.Infof("Running command: %s with output: %s", curlCommand, output)
	err = utils.RetriveFileFromBootstapper(ctx, cl, pcapFileDir, localPCAPPath)
	if err != nil {
		return fmt.Errorf("failed to retrive file from bootstapper:%s to %s, error: %v", pcapFileDir, localPCAPPath, err)
	}
	totalCapturedSize, packetCount, err := getPcapFileDetails_Cgo(localPCAPPath)
	if packetCount == 0 || err != nil {
		return fmt.Errorf("empty filter packets when curl backends, total packet size: %d, packet count: %d, error : %v", totalCapturedSize, packetCount, err)
	}
	klog.Infof("successfully filter packets when curl backends, total packet size: %d, packet count: %d within %d seconds", totalCapturedSize, packetCount, tcpdumpTimeout)
	return nil
}

func getPcapFileDetails_Cgo(filePath string) (totalCapturedSize uint64, packetCount int, err error) {
	handle, openErr := pcap.OpenOffline(filePath)
	if openErr != nil {
		return 0, 0, fmt.Errorf("failed to open pcap file '%s': %w", filePath, openErr)
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	for packet := range packetSource.Packets() {
		meta := packet.Metadata()
		if meta != nil {
			totalCapturedSize += uint64(meta.CaptureLength)
			packetCount++
		} else {
			log.Printf("Warning: Encountered a packet with nil metadata in '%s'", filePath)
		}
	}
	return totalCapturedSize, packetCount, nil
}
