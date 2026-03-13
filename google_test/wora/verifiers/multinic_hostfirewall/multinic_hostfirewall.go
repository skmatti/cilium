package multinic_hostfirewall

import (
	"context"
	"fmt"
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
	"k8s.io/client-go/tools/clientcmd"
	k8sclient "sigs.k8s.io/controller-runtime/pkg/client"

	networkutils "gke-internal.googlesource.com/anthos-networking/test-infra/pkg/network"
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
	blueNetworkCCNPName     = "blue-network-policy"
	greenNetworkCCNPName    = "green-network-policy"
	hostNetworkPodOnWorker0 = "worker0-hostnetwork-pod"
	hostNetworkPodOnWorker1 = "worker1-hostnetwork-pod"
	workerNodeLabel         = "node-role.kubernetes.io/worker"
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
		cl                k8sclient.Client
		nc                *networkclientset.Clientset
		ctx               context.Context
		worker0ifaceGreen networkIface
		worker1ifaceBlue  networkIface
		worker1ifaceGreen networkIface
	)

	BeforeAll(func() {
		ctx, _ = context.WithTimeout(context.Background(), overallTimeout)

		kubeconfig := os.Getenv("KUBECONFIG")
		Expect(kubeconfig).ToNot(BeEmpty(), "KUBECONFIG env var must be set")
		Expect(kubeconfig).To(BeAnExistingFile(), "KUBECONFIG file must exist")

		config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
		Expect(err).NotTo(HaveOccurred(), "Failed to build Kubeconfig")

		cl, err = k8sclient.New(config, k8sclient.Options{Scheme: e2escheme.Scheme()})
		Expect(err).NotTo(HaveOccurred(), "Failed to create controller-runtime client")

		nc, err = networkclientset.NewForConfig(config)
		Expect(err).NotTo(HaveOccurred(), "Failed to create network clientset")

		err = utils.CreateTestNamespace(ctx, cl, testNamespace)
		Expect(err).NotTo(HaveOccurred(), "Failed to create test namespace")

		workerNodes, err := utils.GetRequiredNumberOfNodesByLabel(ctx, cl, workerNodeLabel, 2)
		Expect(err).NotTo(HaveOccurred(), "Failed to fetch worker nodes")

		worker0, worker1 := workerNodes[0], workerNodes[1]
		klog.Infof("worker0: %+v, worker1: %+v", worker0, worker1)

		_, err = utils.CreatePod(ctx, cl, hostNetworkPodOnWorker0, testNamespace, utils.WithNodeSelector(worker0.IP), utils.WithHostNetworking(), utils.WithResponderContainer())
		Expect(err).NotTo(HaveOccurred(), "Failed to create host network pod on worker0")
		_, err = utils.CreatePod(ctx, cl, hostNetworkPodOnWorker1, testNamespace, utils.WithNodeSelector(worker1.IP), utils.WithHostNetworking(), utils.WithResponderContainer())
		Expect(err).NotTo(HaveOccurred(), "Failed to create host network pod on worker1")

		err = utils.CreateL2NetworkAndWaitForReady(ctx, cl, nc, networkv1.ExternalMode, blueNetworkName, blueInterfaceName)
		Expect(err).ToNot(HaveOccurred(), "Failed to create %s and wait for ready", blueNetworkName)
		err = utils.CreateL2NetworkAndWaitForReady(ctx, cl, nc, networkv1.ExternalMode, greenNetworkName, greenInterfaceName)
		Expect(err).ToNot(HaveOccurred(), "Failed to create %s and wait for ready", greenNetworkName)

		worker1IPs, err := FetchPodIPsForInterfaces(ctx, cl, testNamespace, hostNetworkPodOnWorker1, []string{blueInterfaceName, greenInterfaceName})
		Expect(err).NotTo(HaveOccurred())
		Expect(worker1IPs).To(HaveLen(2))
		worker1ifaceBlue = networkIface{ifName: blueInterfaceName, networkName: blueNetworkName, ip: worker1IPs[0]}
		worker1ifaceGreen = networkIface{ifName: greenInterfaceName, networkName: greenNetworkName, ip: worker1IPs[1]}

		worker0IPs, err := FetchPodIPsForInterfaces(ctx, cl, testNamespace, hostNetworkPodOnWorker0, []string{greenInterfaceName})
		Expect(err).NotTo(HaveOccurred())
		Expect(worker0IPs).To(HaveLen(1))
		worker0ifaceGreen = networkIface{ifName: greenInterfaceName, networkName: greenNetworkName, ip: worker0IPs[0]}

		// Blue-network denies ingress from other nodes.
		err = createOrPatchCCNPForNetwork(ctx, cl, blueNetworkCCNPName, blueNetworkName, nil, false)
		Expect(err).ToNot(HaveOccurred())

		// Green-network allows ingress from worker0's green network.
		err = createOrPatchCCNPForNetwork(ctx, cl, greenNetworkCCNPName, greenNetworkName, []ciliumapi.CIDR{ciliumapi.CIDR(worker0ifaceGreen.ip + "/32")}, false)
		Expect(err).ToNot(HaveOccurred())

		klog.Infof("Waiting %s for CCNPs to be enforced", policyEnforcementDelay)
		time.Sleep(policyEnforcementDelay)
	})

	verifyNodeToNodeConnectivity := func(sourcePod, destPod, destIP, networkName string, shouldSucceed bool) {
		klog.Infof("Verifying connectivity from %s to %s on %s network (expecting %t)", sourcePod, destPod, networkName, shouldSucceed)
		err := utils.VerifyCurlFromPod(ctx, testNamespace, sourcePod, destIP, utils.ResponderPort, shouldSucceed, "")
		if shouldSucceed {
			Expect(err).ToNot(HaveOccurred(), "Expected curl from %s to %s on %s network to succeed", sourcePod, destPod, networkName)
		} else {
			Expect(err).ToNot(HaveOccurred(), "Expected curl from %s to %s on %s network to fail", sourcePod, destPod, networkName)
		}
	}

	verifyBootstrapperToNodeConnectivity := func(destIP string, networkName string, shouldSucceed bool) {
		klog.Infof(fmt.Sprintf("Verifying connectivity from bootstrapper to %s on %s network (expecting %v)", destIP, networkName, shouldSucceed))
		err := utils.RunCurlFromBootstrapper(ctx, cl, destIP, utils.ResponderPort, testwait.WaitingMedium)

		if shouldSucceed {
			Expect(err).ToNot(HaveOccurred(), "Expected curl from bootstrapper to %s succeed", destIP)
		} else {
			Expect(err).To(HaveOccurred(), "Expected curl from bootstrapper to %s fail", destIP)
		}
	}

	Describe("Node to Node connectivity test", func() {
		It("validates deny traffic on blue network", func() {
			verifyNodeToNodeConnectivity(hostNetworkPodOnWorker0, hostNetworkPodOnWorker1, worker1ifaceBlue.ip, blueNetworkName, false)
		})

		It("validates allow traffic on green network", func() {
			verifyNodeToNodeConnectivity(hostNetworkPodOnWorker0, hostNetworkPodOnWorker1, worker1ifaceGreen.ip, greenNetworkName, true)
		})
	})

	Describe("Bootstrapper to Node connectivity test", func() {
		BeforeAll(func() {
			By("modifying blue network policy to allow ingress from world")
			err := createOrPatchCCNPForNetwork(ctx, cl, blueNetworkCCNPName, blueNetworkName, nil, true)
			Expect(err).ToNot(HaveOccurred(), "Failed to patch CCNP %s", blueNetworkCCNPName)

			klog.Infof("Waiting %s for modified blue network policy to be enforced", policyEnforcementDelay)
			time.Sleep(policyEnforcementDelay)
		})

		It("validates allow traffic on blue network", func() {
			verifyBootstrapperToNodeConnectivity(worker1ifaceBlue.ip, blueNetworkName, true)
		})

		It("validates deny traffic on green network", func() {
			verifyBootstrapperToNodeConnectivity(worker1ifaceGreen.ip, greenNetworkName, false)
		})
	})

	AfterAll(func() {
		objs := []k8sclient.Object{
			&ciliumv2.CiliumClusterwideNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: blueNetworkCCNPName},
			},
			&ciliumv2.CiliumClusterwideNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: greenNetworkCCNPName},
			},
			&corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{Name: testNamespace},
			},
		}
		for _, obj := range objs {
			Expect(utils.DeleteIfExists(ctx, cl, obj)).NotTo(HaveOccurred())
		}
		for _, obj := range objs {
			Expect(utils.WaitForDeletion(ctx, cl, obj)).NotTo(HaveOccurred())
		}

		for _, networkName := range []string{blueNetworkName, greenNetworkName} {
			Expect(networkutils.TeardownNetwork(ctx, nc, networkName)).NotTo(HaveOccurred())
		}
		for _, networkName := range []string{blueNetworkName, greenNetworkName} {
			networkObj := &networkv1.Network{
				ObjectMeta: metav1.ObjectMeta{
					Name: networkName,
				},
			}
			Expect(utils.WaitForDeletion(ctx, cl, networkObj)).NotTo(HaveOccurred(), "Failed while waiting for network %s to be deleted", networkName)
		}
	})
})
