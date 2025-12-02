package kubevirt

import (
	"context"
	"fmt"
	"net"
	"os"
	"time" // Do not use pkg/time in test code.

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	virtv1 "kubevirt.io/api/core/v1"
	"kubevirt.io/client-go/kubecli"

	networkv1 "github.com/GoogleCloudPlatform/gke-networking-api/apis/network/v1"
	networkclientset "github.com/GoogleCloudPlatform/gke-networking-api/client/network/clientset/versioned"
	"gke-internal.googlesource.com/anthos-networking/test-infra/pkg/client"
	"gke-internal.googlesource.com/anthos-networking/test-infra/pkg/network"
	klog "gke-internal.googlesource.com/syllogi/sanitized-klog/third_party/klogv2"
	gvmv1 "gke-internal.googlesource.com/third_party/cilium/google_test/wora/e2e/pkg/kubevm/vm-controller/api/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/utils/ptr"
	k8sclient "sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	// defaultInitialInterval defines the default initial polling interval as
	// 10s.
	defaultInitialInterval = 10 * time.Second
	// defaultTimeout defines the default timeout value as 10 minutes for the
	// entire operation.
	defaultTimeout                = 20 * time.Minute
	k8sNodeNameLabelKey           = "kubernetes.io/hostname"
	networkInterfaceName          = "eth1"
	vmNetworkName                 = "node-network"
	dhcpNetworkName               = "dhcp-enabled-net"
	namespace                     = "default"
	nfsServiceName                = "nfs-server"
	nfsScName                     = "nfs-csi"
	workerNodeLabelSelectorString = "baremetal.cluster.gke.io/node-pool=np1"
	// cmdConsoleRespDuration is the response timeout for commands run in VM console.
	cmdConsoleRespDuration = 30 * time.Second
	// defaultConsoleRespDuration is the default response timeout for VM console access.
	defaultConsoleRespDuration = 10 * time.Minute
	pingOKExpectation          = "5 received"
	vmBootupWaitTime           = 2 * time.Minute
	dhcpRangeMin               = "10.100.7.100"
	dhcpRangeMax               = "10.100.7.200"
	nfsInstallDuration         = 5 * time.Minute
	defaultInterval            = time.Second
	defaultGetTimeout          = 1 * time.Minute
	nfsCSIComponentNamespace   = "kube-system"
	nfsCSIControllerDeployment = "csi-nfs-controller"
	nfsCSINodeDaemonSet        = "csi-nfs-node"
	numNFSComponent            = 2
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

type CreateVMOptions struct {
	Name             string
	Namespace        string
	IPAddress        string
	VMDiskName       string
	NetworkName      string
	StorageClassName string
}

var dhcpVMOpts = CreateVMOptions{
	Name:             "dhcp-server-vm",
	Namespace:        namespace,
	VMDiskName:       "dhcp-datavolume-disk",
	IPAddress:        "10.100.6.5/21", //This is the static ip must match the one configured in dhcpConfiguratorPodYAML in constant.go file.
	NetworkName:      dhcpNetworkName,
	StorageClassName: "local-shared",
}

var dhcpClient1VMOpts = CreateVMOptions{
	Name:             "dhcp-client-vm-1",
	Namespace:        namespace,
	VMDiskName:       "dhcp-client-disk-1",
	NetworkName:      dhcpNetworkName,
	StorageClassName: "local-shared",
}

var dhcpClient2VMOpts = CreateVMOptions{
	Name:             "dhcp-client-vm-2",
	Namespace:        namespace,
	VMDiskName:       "dhcp-client-disk-2",
	NetworkName:      dhcpNetworkName,
	StorageClassName: nfsScName,
}

var LiveMigrationVMOpts = CreateVMOptions{
	Name:             "dhcp-client-vm-3",
	Namespace:        namespace,
	VMDiskName:       "dhcp-client-disk-3",
	NetworkName:      dhcpNetworkName,
	StorageClassName: nfsScName,
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
	var cl k8sclient.Client

	var kubevirtVMInstance1 *virtv1.VirtualMachineInstance
	var kubevirtVMInstance2 *virtv1.VirtualMachineInstance
	var kubevirtVMInstance3 *virtv1.VirtualMachineInstance
	var dhcpServerVMI *virtv1.VirtualMachineInstance
	var clientVM1VMI *virtv1.VirtualMachineInstance
	var clientVM2VMI *virtv1.VirtualMachineInstance

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

		//Create a network for dhcp
		nc, err = createNetworkClient(config)
		Expect(err).NotTo(HaveOccurred())
		_, err = network.CreateNetwork(ctx, nc, &networkv1.Network{
			ObjectMeta: metav1.ObjectMeta{
				Name: dhcpNetworkName,
			},
			Spec: networkv1.NetworkSpec{
				Type: "L2",
				NodeInterfaceMatcher: networkv1.NodeInterfaceMatcher{
					InterfaceName: ptr.To("vxlan1"),
				},
				IPAMMode:      ptr.To(networkv1.IPAMModeType("External")),
				ExternalDHCP4: ptr.To(true),
				Gateway4:      ptr.To("10.100.0.2"),
				L2NetworkConfig: &networkv1.L2NetworkConfig{
					PrefixLength4: ptr.To(int32(24)),
				},
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

		cl, err = k8sclient.New(config, k8sclient.Options{})
		Expect(err).NotTo(HaveOccurred())
		err = virtv1.AddToScheme(cl.Scheme())
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

		It("validates routes are configured correctly on the VM", func() {
			// The command to show the routing table. A newline character is added to ensure execution.
			showRoutesCmd := "ip route show\n"

			// Define the routes to verify.
			expectedRoutes := []string{"10.240.0.0/13", "172.26.0.0/16"}

			for _, route := range expectedRoutes {
				// Assuming `consoleExec` is a helper that can execute a command and check
				// for an expected string in the output. If not, a more generic
				// helper like `consoleExec` would be needed.
				err := consoleExec(vc, kubevirtVMInstance1, showRoutesCmd, route)
				Expect(err).ShouldNot(HaveOccurred(), fmt.Sprintf("Route %s not found on %s", route, kubevirtVMInstance1.Name))
			}
		})

		It("validate connection of VMs on same node", func() {
			vm2IP, _, _ := net.ParseCIDR(VMTestConfig2.NetworkInterfaces[0].IPAddress)
			pingCmdFromVM1toVM2 := MakePingCommand(vm2IP.String())
			err := consoleExec(vc, kubevirtVMInstance1, pingCmdFromVM1toVM2, pingOKExpectation)
			Expect(err).ShouldNot(HaveOccurred())

			vm1IP, _, _ := net.ParseCIDR(VMTestConfig1.NetworkInterfaces[0].IPAddress)
			pingCmdFromVM2toVM1 := MakePingCommand(vm1IP.String())
			err = consoleExec(vc, kubevirtVMInstance2, pingCmdFromVM2toVM1, pingOKExpectation)
			Expect(err).ShouldNot(HaveOccurred())

		})

		It("validate connection of VMs on different nodes", func() {
			vm3IP, _, _ := net.ParseCIDR(VMTestConfig3.NetworkInterfaces[0].IPAddress)
			pingCmdFromVM1toVM3 := MakePingCommand(vm3IP.String())
			err := consoleExec(vc, kubevirtVMInstance1, pingCmdFromVM1toVM3, pingOKExpectation)
			Expect(err).ShouldNot(HaveOccurred())

			vm1IP, _, _ := net.ParseCIDR(VMTestConfig1.NetworkInterfaces[0].IPAddress)
			pingCmdFromVM3toVM1 := MakePingCommand(vm1IP.String())
			err = consoleExec(vc, kubevirtVMInstance3, pingCmdFromVM3toVM1, pingOKExpectation)
			Expect(err).ShouldNot(HaveOccurred())
		})

		AfterAll(func() {
			klog.Infoln("Tearing down connectivity test VMs")
			vmconfig1 := TearDownConfig{
				VMName:    VMTestConfig1.Name,
				Namespace: VMTestConfig1.Namespace,
				DiskName:  generateDiskName(VMTestConfig1.Name),
			}
			vmconfig2 := TearDownConfig{
				VMName:    VMTestConfig2.Name,
				Namespace: VMTestConfig2.Namespace,
				DiskName:  generateDiskName(VMTestConfig2.Name),
			}
			vmconfig3 := TearDownConfig{
				VMName:    VMTestConfig3.Name,
				Namespace: VMTestConfig3.Namespace,
				DiskName:  generateDiskName(VMTestConfig3.Name),
			}
			err := tearDownTestVM(vmconfig1, restClient, vc, ctx)
			Expect(err).NotTo(HaveOccurred())
			err = tearDownTestVM(vmconfig2, restClient, vc, ctx)
			Expect(err).NotTo(HaveOccurred())
			err = tearDownTestVM(vmconfig3, restClient, vc, ctx)
			Expect(err).NotTo(HaveOccurred())
			err = waitForVMDeletionWithIntervalAndTimeout(ctx, vc, VMTestConfig1.Namespace, VMTestConfig1.Name)
			Expect(err).NotTo(HaveOccurred())
			err = waitForVMDeletionWithIntervalAndTimeout(ctx, vc, VMTestConfig2.Namespace, VMTestConfig2.Name)
			Expect(err).NotTo(HaveOccurred())
			err = waitForVMDeletionWithIntervalAndTimeout(ctx, vc, VMTestConfig3.Namespace, VMTestConfig3.Name)
			Expect(err).NotTo(HaveOccurred())
		})

	})

	Describe("DHCP Server and Live Migration tests", func() {
		BeforeAll(func() {
			waitForVMControllerManagerReady(ctx, c, "Waiting for vm-controller-manager webhook to be ready before NFS installation...")

			err := installNFS(ctx, c)
			if err != nil {
				klog.Infof("NFS installation failed: %s", err)
			}
			Expect(err).ToNot(HaveOccurred(), fmt.Sprintf("NFS installation failed: %v", err))
			klog.Infof("Verifying NFS installation")
			err = waitForNFSReady(c)
			if err != nil {
				klog.Infof("NFS verification failed: %s", err)
			}
			Expect(err).ToNot(HaveOccurred(), fmt.Sprintf("NFS verification failed: %v", err))

			waitForVMControllerManagerReady(ctx, c, "Waiting for vm-controller-manager webhook to be ready after NFS installation...")

			klog.Infoln("Setting up DHCP and Live Migration test VMs")
			enableRoutingOnBootstrap()
			workerNodes, err := workerNodes(ctx, c)
			Expect(err).NotTo(HaveOccurred())
			//Creat dhcp-server-vm and configure it as dhcp server
			createdDHCPServerVM, err := createTestDHCPVirtualMachine(ctx, c, restClient, vc, dhcpVMOpts, workerNodes[0].Name, defaultInitialInterval, defaultTimeout)
			Expect(err).NotTo(HaveOccurred())
			Expect(createdDHCPServerVM).NotTo(BeNil())
			time.Sleep(vmBootupWaitTime)
			err = configureAndAwaitDHCPviaPod(ctx, c, namespace, workerNodes[0].Name, defaultTimeout)
			Expect(err).NotTo(HaveOccurred(), "Failed to configure DHCP server via temporary pod")

			//Create DHCPClient VM on same node
			dhcpClientVM1, err := createTestDHCPVirtualMachine(ctx, c, restClient, vc, dhcpClient1VMOpts, workerNodes[0].Name, defaultInitialInterval, defaultTimeout)
			Expect(err).NotTo(HaveOccurred())
			Expect(dhcpClientVM1).NotTo(BeNil())

			//Create DHCPClient VM on another node
			dhcpClientVM2, err := createTestDHCPVirtualMachine(ctx, c, restClient, vc, dhcpClient2VMOpts, workerNodes[1].Name, defaultInitialInterval, defaultTimeout)
			Expect(err).NotTo(HaveOccurred())
			Expect(dhcpClientVM2).NotTo(BeNil())

			//Create a LiveMigratable VM
			createdVM, err := createTestDHCPVirtualMachine(ctx, c, restClient, vc, LiveMigrationVMOpts, "", defaultInitialInterval, defaultTimeout)
			Expect(err).NotTo(HaveOccurred())
			Expect(createdVM).NotTo(BeNil())
		})

		BeforeEach(func() {
			var err error
			dhcpServerVMI, err = vc.VirtualMachineInstance(dhcpVMOpts.Namespace).Get(ctx, dhcpVMOpts.Name, metav1.GetOptions{})
			Expect(err).ShouldNot(HaveOccurred(), "Failed to get dhcpServerVMI")
			clientVM1VMI, err = vc.VirtualMachineInstance(dhcpClient1VMOpts.Namespace).Get(ctx, dhcpClient1VMOpts.Name, metav1.GetOptions{})
			Expect(err).ShouldNot(HaveOccurred(), "Failed to get clientVM1VMI")
			clientVM2VMI, err = vc.VirtualMachineInstance(dhcpClient2VMOpts.Namespace).Get(ctx, dhcpClient2VMOpts.Name, metav1.GetOptions{})
			Expect(err).ShouldNot(HaveOccurred(), "Failed to get clientVM2VMI")
		})

		It("should verify the client VM's IP is within the configured DHCP range", func() {
			//Verify for dhcpClientVM1
			err := verifyVMIPFromDHCPRange(ctx, vc, dhcpClient1VMOpts.Name, namespace, dhcpRangeMin, dhcpRangeMax)
			Expect(err).NotTo(HaveOccurred())
			//Verify for dhcpClientVM2
			err = verifyVMIPFromDHCPRange(ctx, vc, dhcpClient2VMOpts.Name, namespace, dhcpRangeMin, dhcpRangeMax)
			Expect(err).NotTo(HaveOccurred())
		})

		It("should have network connectivity between DHCP Server and Client DHCVMs", func() {
			klog.Infof("Logging into VM consoles")
			Expect(consoleLogin(vc, dhcpServerVMI)).To(Succeed(), "Failed to log into dhcp-server-vm console")
			Expect(consoleLogin(vc, clientVM1VMI)).To(Succeed(), "Failed to log into client-1-vm console")
			Expect(consoleLogin(vc, clientVM2VMI)).To(Succeed(), "Failed to log into client-2-vm console")
			dhcpServerIP, _, _ := net.ParseCIDR(dhcpVMOpts.IPAddress)
			client1IPStr, err := vmIP(ctx, vc, dhcpClient1VMOpts.Name, dhcpClient1VMOpts.Namespace)
			Expect(err).NotTo(HaveOccurred())
			klog.Infof("DHCP Client VM 1 IP: %s", client1IPStr)
			client2IPStr, err := vmIP(ctx, vc, dhcpClient2VMOpts.Name, dhcpClient2VMOpts.Namespace)
			Expect(err).NotTo(HaveOccurred())
			klog.Infof("DHCP Client VM 2 IP: %s", client2IPStr)
			By("Pinging from DHCP Server to Client 1")
			Expect(consolePing(vc, dhcpServerVMI, client1IPStr)).To(Succeed())
			By("Pinging from Client 1 to DHCP Server")
			Expect(consolePing(vc, clientVM1VMI, dhcpServerIP.String())).To(Succeed())
			By("Pinging from Client 1 to Client 2")
			Expect(consolePing(vc, clientVM1VMI, client2IPStr)).To(Succeed())
			By("Pinging from Client 2 to Client 1")
			Expect(consolePing(vc, clientVM2VMI, client1IPStr)).To(Succeed())
		})

		It("should live Migrate the DHCP Client VM", func() {
			err := performVMLiveMigrationTest(ctx, vc, LiveMigrationVMOpts.Name, namespace)
			Expect(err).NotTo(HaveOccurred())
		})

		It("should Live Migration the same DHCP Client VM back to the original node", func() {
			Expect(performVMLiveMigrationTest(ctx, vc, LiveMigrationVMOpts.Name, namespace)).NotTo(HaveOccurred())
		})

		AfterAll(func() {
			klog.Infoln("Tearing down DHCP and Live Migration test VMs")
			configDHCPVM := TearDownConfig{
				VMName:    dhcpVMOpts.Name,
				Namespace: dhcpVMOpts.Namespace,
				DiskName:  dhcpVMOpts.VMDiskName,
			}
			configDHCPClient1VM := TearDownConfig{
				VMName:    dhcpClient1VMOpts.Name,
				Namespace: dhcpClient1VMOpts.Namespace,
				DiskName:  dhcpClient1VMOpts.VMDiskName,
			}
			configDHCPClient2VM := TearDownConfig{
				VMName:    dhcpClient2VMOpts.Name,
				Namespace: dhcpClient2VMOpts.Namespace,
				DiskName:  dhcpClient2VMOpts.VMDiskName,
			}
			configLiveMigrationVM := TearDownConfig{
				VMName:    LiveMigrationVMOpts.Name,
				Namespace: LiveMigrationVMOpts.Namespace,
				DiskName:  LiveMigrationVMOpts.VMDiskName,
			}
			err := tearDownTestVM(configDHCPVM, restClient, vc, ctx)
			Expect(err).NotTo(HaveOccurred())
			err = tearDownTestVM(configDHCPClient1VM, restClient, vc, ctx)
			Expect(err).NotTo(HaveOccurred())
			err = tearDownTestVM(configDHCPClient2VM, restClient, vc, ctx)
			Expect(err).NotTo(HaveOccurred())
			err = tearDownTestVM(configLiveMigrationVM, restClient, vc, ctx)
			Expect(err).NotTo(HaveOccurred())

			err = waitForVMDeletionWithIntervalAndTimeout(ctx, vc, dhcpVMOpts.Namespace, dhcpVMOpts.Name)
			Expect(err).NotTo(HaveOccurred())
			err = waitForVMDeletionWithIntervalAndTimeout(ctx, vc, dhcpClient1VMOpts.Namespace, dhcpClient1VMOpts.Name)
			Expect(err).NotTo(HaveOccurred())
			err = waitForVMDeletionWithIntervalAndTimeout(ctx, vc, dhcpClient2VMOpts.Namespace, dhcpClient2VMOpts.Name)
			Expect(err).NotTo(HaveOccurred())
			err = waitForVMDeletionWithIntervalAndTimeout(ctx, vc, LiveMigrationVMOpts.Namespace, LiveMigrationVMOpts.Name)
			Expect(err).NotTo(HaveOccurred())
		})

	})

	AfterAll(func() {
		err := network.TeardownNetwork(ctx, nc, vmNetworkName)
		Expect(err).NotTo(HaveOccurred())
		err = network.TeardownNetwork(ctx, nc, dhcpNetworkName)
		Expect(err).NotTo(HaveOccurred())
		err = tearDownServiceAndWait(ctx, cl, namespace, nfsServiceName)
		Expect(err).NotTo(HaveOccurred())
		err = tearDownStatefulSetAndWait(ctx, cl, namespace, nfsServiceName)
		Expect(err).NotTo(HaveOccurred())
		err = tearDownStorageClassAndWait(ctx, cl, nfsScName)
		Expect(err).NotTo(HaveOccurred())
	})
})
