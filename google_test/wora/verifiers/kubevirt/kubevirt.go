package kubevirt

import (
	"context"
	"fmt"
	"net"
	"os"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/utils/ptr"

	networkv1 "github.com/GoogleCloudPlatform/gke-networking-api/apis/network/v1"
	networkclientset "github.com/GoogleCloudPlatform/gke-networking-api/client/network/clientset/versioned"

	"gke-internal.googlesource.com/anthos-networking/test-infra/pkg/client"
	virtv1 "kubevirt.io/api/core/v1"
	"kubevirt.io/client-go/kubecli"

	"gke-internal.googlesource.com/anthos-networking/test-infra/pkg/network"
	klog "gke-internal.googlesource.com/syllogi/sanitized-klog"
	gvmv1 "gke-internal.googlesource.com/third_party/cilium/google_test/wora/e2e/pkg/kubevm/vm-controller/api/v1"
)

const (
	// defaultInitialInterval defines the default initial polling interval as
	// 10s.
	defaultInitialInterval = 10 * time.Second
	// defaultTimeout defines the default timeout value as 10 minutes for the
	// entire operation.
	defaultTimeout                = 10 * time.Minute
	k8sNodeNameLabelKey           = "kubernetes.io/hostname"
	networkInterfaceName          = "eth1"
	vmNetworkName                 = "node-network"
	workerNodeLabelSelectorString = "baremetal.cluster.gke.io/node-pool=np1"
	// cmdConsoleRespDuration is the response timeout for commands run in VM console.
	cmdConsoleRespDuration = 30 * time.Second
	// defaultConsoleRespDuration is the default response timeout for VM console access.
	defaultConsoleRespDuration = 10 * time.Minute
	pingOKExpectation          = "5 received"
)

type NetworkInterfaceConfig struct {
	Name        string
	NetworkName string
	IPAddress   string
}

type VMTestConfig struct {
	Name              string
	Namespace         string
	OSType            gvmv1.OSType
	NetworkInterfaces []NetworkInterfaceConfig
}

var (
	vmruntimePatch = []byte(`[{"op": "replace", "path": "/spec/enabled", "value": true}]`)
	VMTestConfig1  = VMTestConfig{
		Name:      "vm1",
		Namespace: "default",
		OSType:    gvmv1.OSTypeLinux,
		NetworkInterfaces: []NetworkInterfaceConfig{
			{
				Name:        networkInterfaceName,
				NetworkName: vmNetworkName,
				IPAddress:   "10.200.0.21/21",
			}},
	}

	VMTestConfig2 = VMTestConfig{
		Name:      "vm2",
		Namespace: "default",
		OSType:    gvmv1.OSTypeLinux,
		NetworkInterfaces: []NetworkInterfaceConfig{
			{
				Name:        networkInterfaceName,
				NetworkName: vmNetworkName,
				IPAddress:   "10.200.0.22/21",
			}},
	}
	VMTestConfig3 = VMTestConfig{
		Name:      "vm3",
		Namespace: "default",
		OSType:    gvmv1.OSTypeLinux,
		NetworkInterfaces: []NetworkInterfaceConfig{
			{
				Name:        networkInterfaceName,
				NetworkName: vmNetworkName,
				IPAddress:   "10.200.0.23/21",
			}},
	}
	defaultNetworkInterface = gvmv1.InterfaceSpec{
		Name: "eth0",
		NetworkInterfaceSpec: &networkv1.NetworkInterfaceSpec{
			NetworkName: "pod-network",
		},
	}
)

var _ = Describe("Verifiers/Kubevirt", Label("kubevirt"), Ordered, func() {
	var ctx context.Context
	var restClient *rest.RESTClient
	var nc *networkclientset.Clientset
	var c client.Interface
	var vc kubecli.KubevirtClient

	var kubevirtVMInstance1 *virtv1.VirtualMachineInstance
	var kubevirtVMInstance2 *virtv1.VirtualMachineInstance
	var kubevirtVMInstance3 *virtv1.VirtualMachineInstance

	BeforeAll(func() {
		ctx = context.Background()
		kubeconfig := os.Getenv("KUBECONFIG")
		config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
		Expect(err).NotTo(HaveOccurred())

		// Enable vmruntime and check to make sure vmruntime is ready.
		// TODO(b/359964258): Move enable vmruntime out of the test as a
		// separate cluster configuration step.
		restClient, err = createRESTClient(config)
		Expect(err).NotTo(HaveOccurred())
		err = restClient.Patch(types.JSONPatchType).Resource("vmruntimes").Name("vmruntime").Body(vmruntimePatch).Do(ctx).Error()
		Expect(err).NotTo(HaveOccurred())
		err = waitForVMRuntimePreflightcheckSuccess(ctx, restClient, defaultInitialInterval, defaultTimeout)
		Expect(err).NotTo(HaveOccurred(), "VMRuntime preflightcheck failed")
		err = waitForVMRuntimeReady(ctx, restClient, defaultInitialInterval, defaultTimeout)
		Expect(err).ShouldNot(HaveOccurred(), "vmruntime is not ready.")

		// Create network for VM.
		nc, err = createNetworkClient(config)
		Expect(err).NotTo(HaveOccurred())
		_, err = network.CreateNetwork(ctx, nc, &networkv1.Network{
			ObjectMeta: metav1.ObjectMeta{
				Name: vmNetworkName,
			},
			Spec: networkv1.NetworkSpec{
				Type: "L2",
				NodeInterfaceMatcher: networkv1.NodeInterfaceMatcher{
					InterfaceName: ptr.To("vxlan0"),
				},
				Gateway4: ptr.To("10.128.0.1"),
				DNSConfig: &networkv1.DNSConfig{
					Nameservers: []string{"172.26.0.10"},
				},
				Routes: []networkv1.Route{{To: "10.240.0.0/13"}, {To: "172.26.0.0/16"}},
			},
		})
		Expect(err).NotTo(HaveOccurred())

		// prepare the generic client
		c, err = client.NewClientSet(kubeconfig)
		Expect(err).NotTo(HaveOccurred())

		// prepare the kubevirt client
		// Create kubevirt client.
		vc, err = kubecli.GetKubevirtClientFromFlags("", kubeconfig)
		Expect(err).ShouldNot(HaveOccurred())
	})

	It("create all VMs successfully", func() {

		nodeList, err := c.CoreV1().Nodes().List(ctx, metav1.ListOptions{LabelSelector: workerNodeLabelSelectorString})
		Expect(err).NotTo(HaveOccurred())
		if len(nodeList.Items) < 2 {
			klog.Fatalln(fmt.Sprintf("Need at least 2 worker nodes to test cross and same node connectivity, current number of node: %d", len(nodeList.Items)))
		}

		// Create VM1 and VM2 on the first node
		klog.Infoln(fmt.Sprintf("Creating VMs on node: %s", nodeList.Items[0].Name))
		_, err = createTestVMonNode(VMTestConfig1, nodeList.Items[0].Name, restClient, vc, ctx, defaultInitialInterval, defaultTimeout)
		Expect(err).NotTo(HaveOccurred())

		_, err = createTestVMonNode(VMTestConfig2, nodeList.Items[0].Name, restClient, vc, ctx, defaultInitialInterval, defaultTimeout)
		Expect(err).NotTo(HaveOccurred())

		// Create VM3 on other node for cross node connectivity testing.
		_, err = createTestVMonNode(VMTestConfig3, nodeList.Items[1].Name, restClient, vc, ctx, defaultInitialInterval, defaultTimeout)
		Expect(err).NotTo(HaveOccurred())

	})
	Describe("connectivity tests", func() {
		BeforeEach(func() {
			var err error
			kubevirtVMInstance1, err = vc.VirtualMachineInstance(VMTestConfig1.Namespace).Get(ctx, VMTestConfig1.Name, metav1.GetOptions{})
			Expect(err).ShouldNot(HaveOccurred())
			kubevirtVMInstance2, err = vc.VirtualMachineInstance(VMTestConfig2.Namespace).Get(ctx, VMTestConfig2.Name, metav1.GetOptions{})
			Expect(err).ShouldNot(HaveOccurred())
			kubevirtVMInstance3, err = vc.VirtualMachineInstance(VMTestConfig3.Namespace).Get(ctx, VMTestConfig3.Name, metav1.GetOptions{})
			Expect(err).ShouldNot(HaveOccurred())
		})

		It("logs in all VMs successfully", func() {
			err := consoleLogin(vc, kubevirtVMInstance1)
			Expect(err).ShouldNot(HaveOccurred())

			err = consoleLogin(vc, kubevirtVMInstance2)
			Expect(err).ShouldNot(HaveOccurred())

			err = consoleLogin(vc, kubevirtVMInstance3)
			Expect(err).ShouldNot(HaveOccurred())
		})

		It("validate connection of VMs on same node", func() {
			vm2IP, _, _ := net.ParseCIDR(VMTestConfig2.NetworkInterfaces[0].IPAddress)
			pingCmdFromVM1toVM2 := MakePingCommand(vm2IP.String())
			err := consolePing(vc, kubevirtVMInstance1, pingCmdFromVM1toVM2, pingOKExpectation)
			Expect(err).ShouldNot(HaveOccurred())

			vm1IP, _, _ := net.ParseCIDR(VMTestConfig1.NetworkInterfaces[0].IPAddress)
			pingCmdFromVM2toVM1 := MakePingCommand(vm1IP.String())
			err = consolePing(vc, kubevirtVMInstance2, pingCmdFromVM2toVM1, pingOKExpectation)
			Expect(err).ShouldNot(HaveOccurred())

		})

		It("validate connection of VMs on different nodes", func() {
			vm3IP, _, _ := net.ParseCIDR(VMTestConfig3.NetworkInterfaces[0].IPAddress)
			pingCmdFromVM1toVM3 := MakePingCommand(vm3IP.String())
			err := consolePing(vc, kubevirtVMInstance1, pingCmdFromVM1toVM3, pingOKExpectation)
			Expect(err).ShouldNot(HaveOccurred())

			vm1IP, _, _ := net.ParseCIDR(VMTestConfig1.NetworkInterfaces[0].IPAddress)
			pingCmdFromVM3toVM1 := MakePingCommand(vm1IP.String())
			err = consolePing(vc, kubevirtVMInstance3, pingCmdFromVM3toVM1, pingOKExpectation)
			Expect(err).ShouldNot(HaveOccurred())
		})
	})

	AfterAll(func() {
		err := teatDownTestVM(VMTestConfig1, restClient, vc, ctx)
		Expect(err).NotTo(HaveOccurred())
		err = teatDownTestVM(VMTestConfig2, restClient, vc, ctx)
		Expect(err).NotTo(HaveOccurred())
		err = teatDownTestVM(VMTestConfig3, restClient, vc, ctx)
		Expect(err).NotTo(HaveOccurred())
		err = network.TeardownNetwork(ctx, nc, vmNetworkName)
		Expect(err).NotTo(HaveOccurred())
	})

})
