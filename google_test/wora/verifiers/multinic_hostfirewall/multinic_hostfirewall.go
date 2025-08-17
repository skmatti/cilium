package multinic_hostfirewall

import (
	"context"
	"os"
	"time" // Do not use pkg/time in test code.

	networkv1 "github.com/GoogleCloudPlatform/gke-networking-api/apis/network/v1"
	networkclientset "github.com/GoogleCloudPlatform/gke-networking-api/client/network/clientset/versioned"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	ciliumapi "github.com/cilium/cilium/pkg/policy/api"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	k8sclient "sigs.k8s.io/controller-runtime/pkg/client"

	klog "gke-internal.googlesource.com/syllogi/sanitized-klog/third_party/klogv2"
	e2escheme "gke-internal.googlesource.com/third_party/cilium/google_test/wora/e2e/pkg/test/scheme"
	"gke-internal.googlesource.com/third_party/cilium/google_test/wora/e2e/pkg/test/utils"
	testwait "gke-internal.googlesource.com/third_party/cilium/google_test/wora/e2e/pkg/test/wait"
)

const (
	blueNetworkName         = "blue-network"
	greenNetworkName        = "green-network"
	blueInterfaceName       = "vxlan1"
	greenInterfaceName      = "vxlan2"
	testGateway             = "0.0.0.0"
	testNameserver          = "0.0.0.0"
	blueNetworkPolicyName   = "bluenetwork-world-ingress-deny"
	greenNetworkPolicyName  = "greennetwork-world-ingress-allow"
	hostNetworkPodOnWorker0 = "worker0-hostnetwork-pod"
	hostNetworkPodOnWorker1 = "worker1-hostnetwork-pod"
	workerNodeLabel         = "node-role.kubernetes.io/worker="
	curlTimeoutSeconds      = 30
	testNamespace           = "multinic-hostfirewall"
	policyEnforcementDelay  = 30 * time.Second
	overallTimeout          = 20 * time.Minute
)

type networkIface struct {
	ifName      string
	networkName string
	ip          string
}

var _ = Describe("Verifiers/multinic_hostfirewall", Label("multinic-hostfirewall"), Ordered, func() {
	var (
		cl                    k8sclient.Client
		nc                    *networkclientset.Clientset
		err                   error
		config                *rest.Config
		ctx                   context.Context
		worker0ip             string
		worker1ip             string
		worker0Name           string
		worker1Name           string
		cleanupHostPodWorker0 func() // Function to cleanup pod on workernode0
		cleanupHostPodWorker1 func() // Function to cleanup pod on workernode1
		allowWorldEntity      bool
		clientset             *kubernetes.Clientset
		worker0ifaceGreen     networkIface
		worker1ifaceBlue      networkIface
		worker1ifaceGreen     networkIface
	)

	BeforeAll(func() {
		ctx, _ = context.WithTimeout(context.Background(), overallTimeout)

		kubeconfig := os.Getenv("KUBECONFIG")
		Expect(kubeconfig).ToNot(BeEmpty(), "KUBECONFIG env var must be set")
		Expect(kubeconfig).To(BeAnExistingFile(), "KUBECONFIG file must exist")

		config, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
		Expect(err).NotTo(HaveOccurred(), "Failed to build Kubeconfig")

		s := e2escheme.Scheme()

		cl, err = k8sclient.New(config, k8sclient.Options{Scheme: s})
		Expect(err).NotTo(HaveOccurred(), "Failed to create controller-runtime client")

		nc, err = networkclientset.NewForConfig(config)
		Expect(err).NotTo(HaveOccurred(), "Failed to create network clientset")

		clientset, err = kubernetes.NewForConfig(config)
		Expect(err).NotTo(HaveOccurred(), "Failed to create Kubernetes clientset")

		klog.Infof("Creating test namespace %s", testNamespace)
		err = utils.CreateTestNamespace(ctx, cl, testNamespace)
		Expect(err).NotTo(HaveOccurred(), "Failed to create test namespace %s", testNamespace)

		klog.Infof("Listing worker nodes using label %q", workerNodeLabel)
		nodeList, err := clientset.CoreV1().Nodes().List(ctx, metav1.ListOptions{LabelSelector: workerNodeLabel})
		Expect(err).NotTo(HaveOccurred(), "Failed to fetch worker nodes")
		Expect(nodeList.Items).ShouldNot(BeEmpty(), "No worker nodes found")
		Expect(len(nodeList.Items)).To(BeNumerically(">=", 2), "Expected at least two worker nodes with label %q for this test, found %d", workerNodeLabel, len(nodeList.Items))

		worker0Name = nodeList.Items[0].Name
		Expect(worker0Name).NotTo(BeEmpty(), "Could not find name for the workernode0")
		worker1Name = nodeList.Items[1].Name
		Expect(worker1Name).NotTo(BeEmpty(), "Could not find name for the workernode1")

		worker0ip = nodeList.Items[0].Status.Addresses[0].Address
		Expect(worker0ip).NotTo(BeEmpty(), "Couldn't find ip for workernode0")
		worker1ip = nodeList.Items[1].Status.Addresses[0].Address
		Expect(worker1ip).NotTo(BeEmpty(), "Couldn't find ip for workernode1")

		// Creating Host Network Pods on workernode0 and workernode1
		cleanupHostPodWorker0, err = utils.CreatePod(ctx, cl, hostNetworkPodOnWorker0, testNamespace, utils.WithNodeSelector(worker0ip), utils.WithHostNetworking(), utils.WithResponderContainer())
		Expect(err).NotTo(HaveOccurred(), "Failed to create host network pod %s on node %s", hostNetworkPodOnWorker0, worker0ip)
		cleanupHostPodWorker1, err = utils.CreatePod(ctx, cl, hostNetworkPodOnWorker1, testNamespace, utils.WithNodeSelector(worker1ip), utils.WithHostNetworking(), utils.WithResponderContainer())
		Expect(err).NotTo(HaveOccurred(), "Failed to create host network pod %s on node %s", hostNetworkPodOnWorker1, worker1ip)
		klog.Infof("Created host network pods: %s and %s on nodes %s and %s", hostNetworkPodOnWorker0, worker0ip, hostNetworkPodOnWorker1, worker1ip)

		// Fetch IP for worker1 node (blue-network interface and green-network interface)
		worker1Interfaces := []string{blueInterfaceName, greenInterfaceName}
		worker1IPs, err := FetchPodVxlanIPs(ctx, cl, hostNetworkPodOnWorker1, testNamespace, worker1Interfaces)
		Expect(len(worker1IPs)).To(BeNumerically(">=", 2), "Expected at least two IPs for interfaces %v in pod %s/%s, got %d", worker1Interfaces, testNamespace, hostNetworkPodOnWorker1, len(worker1IPs))
		Expect(err).NotTo(HaveOccurred(), "Failed to fetch IPs for interfaces %v in pod %s/%s", worker1Interfaces, testNamespace, hostNetworkPodOnWorker1)
		worker1ifaceBlue = networkIface{ifName: blueInterfaceName, networkName: blueNetworkName, ip: worker1IPs[0]}
		worker1ifaceGreen = networkIface{ifName: greenInterfaceName, networkName: greenNetworkName, ip: worker1IPs[1]}
		klog.Infof("Worker1 info: Node: %s(IP=%s), Hostnetworkpod: %s, Interfaces: %s(IP=%s), %s (IP=%s)", worker1Name, worker1ip, hostNetworkPodOnWorker1, blueInterfaceName, worker1ifaceBlue.ip, worker1ifaceGreen.ifName, worker1ifaceGreen.ip)

		// Fetch IP for worker0 (green interface)
		worker0Interfaces := []string{greenInterfaceName}
		worker0IPs, err := FetchPodVxlanIPs(ctx, cl, hostNetworkPodOnWorker0, testNamespace, worker0Interfaces)
		Expect(len(worker0IPs)).To(BeNumerically(">=", 1), "Expected at least one IP for interfaces %v in pod %s/%s, got %d", worker0Interfaces, testNamespace, hostNetworkPodOnWorker0, len(worker0IPs))
		Expect(err).NotTo(HaveOccurred(), "Failed to fetch IPs for interfaces %v in pod %s/%s", worker0Interfaces, testNamespace, hostNetworkPodOnWorker0)
		worker0ifaceGreen = networkIface{ifName: greenInterfaceName, networkName: greenNetworkName, ip: worker0IPs[0]}
		klog.Infof("Worker0 info: Node: %s(IP=%s), Hostnetworkpod: %s, Interfaces: %s (IP=%s)", worker0Name, worker1ip, hostNetworkPodOnWorker1, worker0ifaceGreen.ifName, worker0ifaceGreen.ip)

		ipamModeExternal := networkv1.ExternalMode
		expectedNodes := []string{worker0Name, worker1Name} // Nodes where networks should be provisioned

		// Create and validate blue-network
		err = utils.CreateL2Network(ctx, nc, ipamModeExternal, blueNetworkName, blueInterfaceName, testGateway, testNameserver)
		Expect(err).ToNot(HaveOccurred(), "Failed to create blue network")
		err = validateNetworkReadiness(ctx, cl, blueNetworkName, expectedNodes)
		Expect(err).ToNot(HaveOccurred(), "validateNetworkReadiness for %s failed", blueNetworkName)

		// Create and validate green-network
		err = utils.CreateL2Network(ctx, nc, ipamModeExternal, greenNetworkName, greenInterfaceName, testGateway, testNameserver)
		Expect(err).ToNot(HaveOccurred(), "Failed to create green network")
		err = validateNetworkReadiness(ctx, cl, greenNetworkName, expectedNodes)
		Expect(err).ToNot(HaveOccurred(), "validateNetworkReadiness for %s failed", greenNetworkName)

		allowWorldEntity = false
		// Blue-network denies ingress from other nodes
		err = createOrPatchCCNPForMultinic(ctx, cl, blueNetworkPolicyName, blueNetworkName, []ciliumapi.CIDR{}, allowWorldEntity)
		Expect(err).ToNot(HaveOccurred(), "Failed to create CCNP %s", blueNetworkPolicyName)
		err = validateCCNPExistence(ctx, cl, blueNetworkPolicyName)
		Expect(err).NotTo(HaveOccurred(), "Failed to validate existence of %s", blueNetworkPolicyName)

		// Green-network allows ingress from workernode0's green IP
		err = createOrPatchCCNPForMultinic(ctx, cl, greenNetworkPolicyName, greenNetworkName, []ciliumapi.CIDR{ciliumapi.CIDR(worker0ifaceGreen.ip + "/32")}, allowWorldEntity)
		Expect(err).ToNot(HaveOccurred(), "Failed to create CCNP %s", greenNetworkPolicyName)
		err = validateCCNPExistence(ctx, cl, greenNetworkPolicyName)
		Expect(err).NotTo(HaveOccurred(), "Failed to validate existence of %s", greenNetworkPolicyName)

		klog.Infof("Waiting %v for Cilium policies to be enforced...", policyEnforcementDelay)
		time.Sleep(policyEnforcementDelay)
		klog.Info("Proceeding with connectivity validation. Multinic test setup complete")
	})

	Context("Connectivity Validation", func() {
		It("Validates connectivity between nodes based on policies", func() {
			klog.Infof("Attempting curl from %s to %s (%s) on blue-network (expecting failure)", hostNetworkPodOnWorker0, hostNetworkPodOnWorker1, worker1ifaceBlue.ip)
			err = utils.VerifyCurlFromPod(ctx, testNamespace, hostNetworkPodOnWorker0, worker1ifaceBlue.ip, utils.ResponderPort, false, "")
			Expect(err).ToNot(HaveOccurred(), "Curl from %s to %s via blue-network %s should have failed due to policy, but succeeded.", hostNetworkPodOnWorker0, hostNetworkPodOnWorker1, blueInterfaceName)
			klog.Infof("Curl from %s to %s on blue-network %s failed as expected.", hostNetworkPodOnWorker0, hostNetworkPodOnWorker1, blueInterfaceName)

			klog.Infof("Attempting curl from %s to %s (%s) on green-network (expecting success)", hostNetworkPodOnWorker0, hostNetworkPodOnWorker1, worker1ifaceGreen.ip)
			err = utils.VerifyCurlFromPod(ctx, testNamespace, hostNetworkPodOnWorker0, worker1ifaceGreen.ip, utils.ResponderPort, true, "")
			Expect(err).NotTo(HaveOccurred(), "Curl from %s to %s via green-network %s failed, but should have succeeded.", hostNetworkPodOnWorker0, hostNetworkPodOnWorker1, greenInterfaceName)
			klog.Infof("Curl from  %s to %s on green-network %s succeeded as expected.", hostNetworkPodOnWorker0, hostNetworkPodOnWorker1, greenInterfaceName)
		})

		It("Validates connectivity from external source(bootstrapper)", func() {
			// Deleting green-network policy and recreating the CCNP policy to allow ingress from EntityWorld
			klog.Infof("Modifying policy %s to allow EntityWorld", greenNetworkPolicyName)
			allowWorldEntity = true

			err = createOrPatchCCNPForMultinic(ctx, cl, greenNetworkPolicyName, greenNetworkName, []ciliumapi.CIDR{ciliumapi.CIDR(worker1ifaceGreen.ip + "/32")}, allowWorldEntity)
			Expect(err).ToNot(HaveOccurred(), "Failed to Patch CCNP %s with EntityWorld", greenNetworkPolicyName)

			klog.Infof("Waiting %v for modified Cilium policies to be enforced...", policyEnforcementDelay)
			time.Sleep(policyEnforcementDelay)
			klog.Info("Proceeding with external connectivity validation.")

			klog.Infof("Attempting curl from bootstrapper to %s (%s) via green-network (expecting success within 30s)", hostNetworkPodOnWorker1, worker1ifaceGreen.ip)
			curlSuccessCtx, curlSuccessCancel := context.WithTimeout(ctx, 10*time.Second)
			err = utils.RunCurlFromBootstrapper(curlSuccessCtx, cl, worker1ifaceGreen.ip, utils.ResponderPort, testwait.WaitingShort)
			curlSuccessCancel()
			Expect(err).NotTo(HaveOccurred(), "Curl from bootstrapper to worker1 via green-network failed, but should have succeeded.")
			klog.Info("Curl from bootstrapper on green-network succeeded within 30s as expected.")

			klog.Infof("Attempting curl from bootstrapper to %s (%s) via blue-network (expecting failure within 30s)", hostNetworkPodOnWorker1, worker1ifaceBlue.ip)
			curlFailCtx, curlFailCancel := context.WithTimeout(ctx, 10*time.Second)
			err = utils.RunCurlFromBootstrapper(curlFailCtx, cl, worker1ifaceBlue.ip, utils.ResponderPort, testwait.WaitingShort)
			curlFailCancel()
			Expect(err).To(HaveOccurred(), "Curl from bootstrapper on blue-network succeeded, but should have failed")
			klog.Infof("Curl from bootstrapper on blue-network did not succeed within 30s timeout, as expected.")
		})
	})

	AfterAll(func() {
		// Cleanup host network pods
		if cleanupHostPodWorker0 != nil {
			klog.Infof("Cleaning up host network pod %s", hostNetworkPodOnWorker0)
			cleanupHostPodWorker0()
		}
		if cleanupHostPodWorker1 != nil {
			klog.Infof("Cleaning up host network pod %s", hostNetworkPodOnWorker1)
			cleanupHostPodWorker1()
		}

		// Delete CCNPs
		klog.Infof("Deleting CiliumClusterwideNetworkPolicy %s", blueNetworkPolicyName)
		networkPolicy := &ciliumv2.CiliumClusterwideNetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name: blueNetworkPolicyName,
			},
		}
		err = utils.DeleteAndWait(ctx, cl, networkPolicy)
		Expect(err).NotTo(HaveOccurred(), "Error during cleanup of policy %s", blueNetworkPolicyName)

		klog.Infof("Deleting CiliumClusterwideNetworkPolicy %s", greenNetworkPolicyName)
		networkPolicy = &ciliumv2.CiliumClusterwideNetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name: greenNetworkPolicyName,
			},
		}
		err = utils.DeleteAndWait(ctx, cl, networkPolicy)
		Expect(err).NotTo(HaveOccurred(), "Error during cleanup of policy %s", greenNetworkPolicyName)

		// Delete test namespace
		klog.Infof("Deleting test namespace %s", testNamespace)
		nsToDelete := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: testNamespace}}
		err = utils.DeleteAndWait(ctx, cl, nsToDelete)
		Expect(err).NotTo(HaveOccurred(), "Failed to delete test namespace %s", testNamespace)

		// Delete the networks
		nodesToCleanup, err := GetAllNodeNames(ctx, cl)
		if err != nil || len(nodesToCleanup) == 0 {
			klog.Warningf("Worker node names were not available for cleanup checks. Skipping annotation verification during network deletion.")
		}
		klog.Infof("Deleting the Network %s", blueNetworkName)
		err = deleteAndWaitForNetworkDeletion(ctx, cl, nc, blueNetworkName, nodesToCleanup)
		Expect(err).NotTo(HaveOccurred(), "Failed to tear down blue-network")
		klog.Infof("Deleting the Network %s", greenNetworkName)
		err = deleteAndWaitForNetworkDeletion(ctx, cl, nc, greenNetworkName, nodesToCleanup)
		Expect(err).NotTo(HaveOccurred(), "Failed to tear down green-network")

		klog.Info("Multinic test cleanup complete")
	})

})
