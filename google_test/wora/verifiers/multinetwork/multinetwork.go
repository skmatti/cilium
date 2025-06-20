package multinetwork

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time" // Do not use pkg/time in test code.

	networkv1 "github.com/GoogleCloudPlatform/gke-networking-api/apis/network/v1"
	networkclientset "github.com/GoogleCloudPlatform/gke-networking-api/client/network/clientset/versioned"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	crclient "sigs.k8s.io/controller-runtime/pkg/client"

	"gke-internal.googlesource.com/anthos-networking/test-infra/pkg/artifact"
	"gke-internal.googlesource.com/anthos-networking/test-infra/pkg/client"
	"gke-internal.googlesource.com/anthos-networking/test-infra/pkg/network"
	klog "gke-internal.googlesource.com/syllogi/sanitized-klog/third_party/klogv2"
	e2escheme "gke-internal.googlesource.com/third_party/cilium/google_test/wora/e2e/pkg/test/scheme"
	"gke-internal.googlesource.com/third_party/cilium/google_test/wora/e2e/pkg/test/utils"
)

const (
	additionalNetworkName         = "vlanl2"
	clusterCIDRConfigName         = "cccl2"
	podInterfaceName              = "eth1"
	nodeSelectorKey               = "baremetal.cluster.gke.io/node-pool"
	additionalNetworkNodePoolName = "np1"
	maskSizeForAllNodesCombined   = 27
	testNamespace                 = "default"
	cidrBlockNamePrefix           = "test-block"
	hercClientTimeout             = 120 * time.Second
	nwSelectorKey                 = "networking.gke.io/network"
	// cleanupPods sets the default value of whether the deployed test pod will be
	// deleted after test finish. Here true means the test pod will be cleaned up
	// after the test run.
	cleanupPods        = true
	podsTimeout        = 30 * time.Minute
	pingTimeoutSeconds = 10
	hostNetworkPodName = "host-nw-pod"
)

// IPs set up by add-vxlans binary on vxlan1 interfaces on each node
var additionalNodeNetworkIPs = []string{
	"10.100.0.2",
	"10.100.0.3",
	"10.100.0.4",
	"10.100.0.5",
}

var _ = Describe("Verifiers/multinetwork", Label("multinetwork"), Ordered, func() {
	var (
		c                         client.Interface
		cl                        crclient.Client
		dc                        *dynamic.DynamicClient
		nc                        *networkclientset.Clientset
		err                       error
		nodeInterfaceName         string
		additionalNodeNetworkInfo *artifact.NodeNetworkInfo
		cidr                      string
	)
	ctx := context.Background()
	BeforeAll(func() {
		kubeconfig := os.Getenv("KUBECONFIG")
		c, err = client.NewClientSet(kubeconfig)
		Expect(err).NotTo(HaveOccurred())

		config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
		Expect(err).NotTo(HaveOccurred())

		dc, err = createDynamicClient(config)
		Expect(err).NotTo(HaveOccurred())

		nc, err = createNetworkClient(config)
		Expect(err).NotTo(HaveOccurred())

		scheme := e2escheme.Scheme()
		// create a controller runtime client
		cl, err = crclient.New(config, crclient.Options{Scheme: scheme})
		Expect(err).NotTo(HaveOccurred())

		hercEnvJsonFilePath := filepath.Join(filepath.Dir(kubeconfig), "herc_env.json")
		_, err = os.Stat(hercEnvJsonFilePath)
		if errors.Is(err, os.ErrNotExist) {
			// GDC-SO on GCE nodes are brought up with 3 node interfaces:
			// vxlan0 (default network) (range: )
			// vxlan1 (additional node network 1) (range: 10.100.0.0/21)
			// vxlan2 (additional node network 2) (range: 10.150.0.0/21)
			// These vxlan interfaces are setup on all the GCE nodes of the cluster: worker nodes,
			// control plane nodes and bootstrapper node and act as the k8s node interfaces.
			additionalNodeNetworkInfo = &artifact.NodeNetworkInfo{
				NetworkName:             "placeholder-additional-network",
				Netmask:                 "255.255.248.0", // /21
				GatewayServer:           "10.100.0.1",
				GatewayServerSubnetMask: "21",
			}
			nodeInterfaceName = "vxlan1"
			// pod CIDR from the larger L2 network (vxlan1)
			cidr = fmt.Sprintf("10.100.5.0/%d", maskSizeForAllNodesCombined)
			klog.Info("Running on ABM on GCE.")
		} else {
			Expect(err).NotTo(HaveOccurred())
			Expect(filepath.IsAbs(hercEnvJsonFilePath)).To(BeTrue())
			additionalNodeNetworkInfo, err = artifact.ExtractNodeNetworkInfo(hercEnvJsonFilePath)
			Expect(err).NotTo(HaveOccurred())

			if additionalNodeNetworkInfo.Location == "atl_shared" {
				// Get herc provisioner client.
				// Create a herc client connecting to environment.
				provisioner, err := network.GetProvisionerClient(additionalNodeNetworkInfo.Location)
				Expect(err).NotTo(HaveOccurred())

				// Set external API context timeout
				ctx, cancel := context.WithTimeout(context.Background(), hercClientTimeout)
				defer cancel()

				// Reserve IPv4 CIDR block.
				cidr, err = network.ReserveIPv4CIDRBlock(
					ctx,
					additionalNodeNetworkInfo,
					fmt.Sprintf("%s-%s", cidrBlockNamePrefix, additionalNodeNetworkInfo.EnvironmentID),
					maskSizeForAllNodesCombined,
					provisioner,
				)
				Expect(err).NotTo(HaveOccurred())
				nodeInterfaceName = "ens224"
			} else {
				cidr = fmt.Sprintf("%s/%d", additionalNodeNetworkInfo.GatewayServer, maskSizeForAllNodesCombined)
				nodeInterfaceName = "bond0"
			}
			klog.Infof("Running on ABM on %s.", additionalNodeNetworkInfo.Location)
		}
		s, _ := json.MarshalIndent(additionalNodeNetworkInfo, "", "\t")
		networkConfigLogMessage := fmt.Sprintf("Running multinetwork test, use following info to create network:\n%s\nnodeInterfaceName: %s", s, nodeInterfaceName)
		klog.Info(networkConfigLogMessage)

		prefixLength, _ := net.IPMask(net.ParseIP(additionalNodeNetworkInfo.Netmask).To4()).Size()
		prefixLength4 := int32(prefixLength)
		ipamModeInternal := networkv1.InternalMode
		networkObject := networkv1.Network{
			ObjectMeta: metav1.ObjectMeta{
				Name: additionalNetworkName,
			},
			Spec: networkv1.NetworkSpec{
				Type: "L2",
				NodeInterfaceMatcher: networkv1.NodeInterfaceMatcher{
					InterfaceName: &nodeInterfaceName,
				},
				Gateway4: &additionalNodeNetworkInfo.GatewayServer,
				L2NetworkConfig: &networkv1.L2NetworkConfig{
					PrefixLength4: &prefixLength4,
				},
				IPAMMode: &ipamModeInternal,
				DNSConfig: &networkv1.DNSConfig{
					Nameservers: []string{"8.8.8.8"},
				},
			},
		}

		_, err = network.CreateNetwork(ctx, nc, &networkObject)
		Expect(err).NotTo(HaveOccurred())

		_, podIPv4cidr, _ := net.ParseCIDR(cidr)
		_, err = network.CreateClusterCIDRConfig(ctx, dc, clusterCIDRConfigName, podIPv4cidr.String(), additionalNetworkName, metav1.LabelSelector{})
		Expect(err).NotTo(HaveOccurred())

		err = createWorkloadPodOnEachNode(c, ctx, additionalNetworkNodePoolName, additionalNetworkName, podInterfaceName, testNamespace)
		Expect(err).NotTo(HaveOccurred())
	})

	It("can list correct number of pods", func() {
		allWorkerNode, err := c.CoreV1().Nodes().List(ctx, metav1.ListOptions{LabelSelector: fmt.Sprintf("%s=%s", nodeSelectorKey, additionalNetworkNodePoolName)})
		Expect(err).NotTo(HaveOccurred())
		allTestWorkloadPods, err := c.CoreV1().Pods(testNamespace).List(ctx, metav1.ListOptions{})
		Expect(err).NotTo(HaveOccurred())
		Expect(allTestWorkloadPods.Items).To(HaveLen(len(allWorkerNode.Items)))
	})

	It("can validate the communication between multi network pods on each node", func() {
		allTestWorkloadPods, _ := c.CoreV1().Pods(testNamespace).List(ctx, metav1.ListOptions{})
		allNodes, _ := c.CoreV1().Nodes().List(context.Background(), metav1.ListOptions{LabelSelector: fmt.Sprintf("%s=%s", nodeSelectorKey, additionalNetworkNodePoolName)})
		err = network.ValidateMultiNetworkPodConnectivityFromEachNode(ctx, nc, c, dc, testNamespace, additionalNetworkName, podInterfaceName, allTestWorkloadPods, allNodes, cleanupPods, podsTimeout)
		Expect(err).NotTo(HaveOccurred())
	})

	It("can validate reachability of multinetwork pod behind a multinetwork L2 nodeport service ", func() {
		allNodes, _ := c.CoreV1().Nodes().List(context.Background(), metav1.ListOptions{LabelSelector: fmt.Sprintf("%s=%s", nodeSelectorKey, additionalNetworkNodePoolName)})

		// create a host network pod on a node that allows us to identify the node network IPs on additional node interfaces
		_, err := utils.CreatePod(ctx, cl, hostNetworkPodName, testNamespace,
			utils.WithHostNetworking(),
			utils.WithNodeName(allNodes.Items[0].Name))
		Expect(err).NotTo(HaveOccurred())
		cidr, err := utils.NodeInterfaceIPFromPod(ctx, hostNetworkPodName, nodeInterfaceName, testNamespace)
		cidr = strings.TrimSuffix(cidr, "\n")
		Expect(err).NotTo(HaveOccurred())

		ip, _, err := net.ParseCIDR(cidr)
		Expect(err).NotTo(HaveOccurred())
		additionalNodeNetworkIP := ip.String()
		Expect(err).NotTo(HaveOccurred())

		// create multinic test pods with label selector on any one node that we know the additional node interface IP for.
		labelKey := "app"
		labelValue := "svc-test"
		nwSelectorValue := additionalNetworkName

		// Test ExternalTrafficPolicy:Local behaviour by curling node0 and pod on node0
		nodeportTestPodName := "nodeport-svc-test-pod"
		cleanup, err := utils.CreatePodWithNetworkInterfaces(ctx, cl, nodeportTestPodName, testNamespace,
			[]utils.NetworkInfo{
				{
					InterfaceName: "eth0",
					NetworkName:   networkv1.DefaultPodNetworkName,
				},
				{
					InterfaceName: "eth1",
					NetworkName:   additionalNetworkName,
					IPAMMode:      "Internal",
					IsDefault:     true,
				},
			},
			nil,
			utils.WithLabel(labelKey, labelValue),
			utils.WithNodeName(allNodes.Items[0].Name),
			utils.WithContainers([]corev1.Container{utils.ResponderContainer}),
		)
		Expect(err).NotTo(HaveOccurred())

		// create multinetwork nodeport svc on additional network with pod selector
		svcName := "nodeport-svc-test-local"
		svc := corev1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name:      svcName,
				Namespace: testNamespace,
			},
			Spec: corev1.ServiceSpec{
				Type:                  corev1.ServiceTypeNodePort,
				ExternalTrafficPolicy: corev1.ServiceExternalTrafficPolicyTypeLocal,
				Selector: map[string]string{
					labelKey:      labelValue,
					nwSelectorKey: nwSelectorValue,
				},
				Ports: []corev1.ServicePort{
					{
						Name: "http",
						Port: int32(8080),
						TargetPort: intstr.IntOrString{
							Type:   intstr.Int,
							IntVal: 8080,
						},
					},
				},
			},
		}

		err = utils.CreateNodeportService(ctx, cl, &svc)
		Expect(err).NotTo(HaveOccurred())

		// Wait for service NodePort to come up.
		err, assignedNodePort := utils.NodePortReadiness(ctx, cl, svcName, testNamespace, corev1.ServiceTypeNodePort)
		Expect(err).NotTo(HaveOccurred())

		Expect(assignedNodePort).To(BeNumerically(">", 0), "NodePort should be assigned and non-zero")

		// run curl from bootstrapper on nodeport service
		err = utils.RunCurlFromBootstrapper(ctx, cl, additionalNodeNetworkIP, int32(assignedNodePort))
		Expect(err).NotTo(HaveOccurred())

		klog.Infof("Successfully tested externalTrafficPolicy: Local behaviour for L2 multinetwork nodeport services")

		// delete the previously deployed pod on node0
		cleanup()
		err = utils.WaitForPodDeletion(ctx, cl, nodeportTestPodName, testNamespace)
		Expect(err).ToNot(HaveOccurred())

		// Test ExternalTrafficPolicy: Cluster behaviour by curling node0 and pod on node1
		cleanup, err = utils.CreatePodWithNetworkInterfaces(ctx, cl, nodeportTestPodName, testNamespace,
			[]utils.NetworkInfo{
				{
					InterfaceName: "eth0",
					NetworkName:   networkv1.DefaultPodNetworkName,
				},
				{
					InterfaceName: "eth1",
					NetworkName:   additionalNetworkName,
					IPAMMode:      "Internal",
					IsDefault:     true,
				},
			},
			nil,
			utils.WithLabel(labelKey, labelValue),
			utils.WithNodeName(allNodes.Items[1].Name), // deploy on node 1
			utils.WithContainers([]corev1.Container{utils.ResponderContainer}),
		)
		Expect(err).NotTo(HaveOccurred())

		// create multinetwork with ETP:Cluster nodeport svc on additional network with pod selector
		svcName = "nodeport-svc-test-cluster"
		svc = corev1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name:      svcName,
				Namespace: testNamespace,
			},
			Spec: corev1.ServiceSpec{
				Type:                  corev1.ServiceTypeNodePort,
				ExternalTrafficPolicy: corev1.ServiceExternalTrafficPolicyTypeLocal,
				Selector: map[string]string{
					labelKey:      labelValue,
					nwSelectorKey: nwSelectorValue,
				},
				Ports: []corev1.ServicePort{
					{
						Name: "http",
						Port: int32(8080),
						TargetPort: intstr.IntOrString{
							Type:   intstr.Int,
							IntVal: 8080,
						},
					},
				},
			},
		}

		err = utils.CreateNodeportService(ctx, cl, &svc)
		Expect(err).NotTo(HaveOccurred())

		// Wait for service NodePort to come up.
		err, assignedNodePort = utils.NodePortReadiness(ctx, cl, svcName, testNamespace, corev1.ServiceTypeNodePort)
		Expect(err).NotTo(HaveOccurred())

		Expect(assignedNodePort).To(BeNumerically(">", 0), "NodePort should be assigned and non-zero")

		err = utils.RunPingFromPodWithTimeoutLimit(ctx, nodeportTestPodName, testNamespace, additionalNodeNetworkIP, pingTimeoutSeconds)
		Expect(err).NotTo(HaveOccurred())

		// run curl from bootstrapper on nodeport service
		err = utils.RunCurlFromBootstrapper(ctx, cl, additionalNodeNetworkIP, int32(assignedNodePort))
		Expect(err).NotTo(HaveOccurred())

		klog.Infof("Successfully tested externalTrafficPolicy: Cluster behaviour for L2 multinetwork nodeport services")

		cleanup()
		err = utils.WaitForPodDeletion(ctx, cl, nodeportTestPodName, testNamespace)
		Expect(err).ToNot(HaveOccurred())

		// delete multinetwork nodeport service
		err = utils.DeleteIfExists(ctx, cl, &svc, "service")
		Expect(err).NotTo(HaveOccurred())
	})

	It("can validate reachability of multinetwork pod behind a L2 multinetwork LoadBalancer service ", func() {

		// create IPAddressPool and L2Advertisements for metalLB to handle IPAM and advertise ranges for LB services
		secondaryNetworkLBRanges := []string{"10.100.7.10/30"}

		ipAddrPoolName := "lb-ipaddrpool"
		annotations := map[string]string{
			"networking.gke.io/network": additionalNetworkName,
		}
		l2AdvertisementName := "lb-l2adv"
		_, err := utils.CreateIPAddressPool(ctx, dc, ipAddrPoolName, annotations, secondaryNetworkLBRanges)
		Expect(err).NotTo(HaveOccurred())
		_, err = utils.CreateL2Advertisement(ctx, dc, l2AdvertisementName, []string{ipAddrPoolName})
		Expect(err).NotTo(HaveOccurred())

		// create multinic test pods with label selector on any one node that we know the additional node interface IP for.
		labelKey := "app"
		labelValue := "lb-svc-test"
		nwSelectorValue := additionalNetworkName
		lbTestPodName := "mn-lb-svc-test-pod"
		cleanup, err := utils.CreatePodWithNetworkInterfaces(ctx, cl, lbTestPodName, testNamespace,
			[]utils.NetworkInfo{
				{
					InterfaceName: "eth0",
					NetworkName:   networkv1.DefaultPodNetworkName,
				},
				{
					InterfaceName: "eth1",
					NetworkName:   additionalNetworkName,
					IPAMMode:      "Internal",
					IsDefault:     true,
				},
			},
			nil,
			utils.WithLabel(labelKey, labelValue),
			utils.WithContainers([]corev1.Container{utils.ResponderContainer}),
		)
		Expect(err).NotTo(HaveOccurred())

		// create multinetwork LoadBalancer svc on additional network with pod selector
		svcName := "mn-lb-svc-test"
		svc := corev1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name:      svcName,
				Namespace: testNamespace,
			},
			Spec: corev1.ServiceSpec{
				Type: corev1.ServiceTypeLoadBalancer,
				Selector: map[string]string{
					labelKey:      labelValue,
					nwSelectorKey: nwSelectorValue,
				},
				Ports: []corev1.ServicePort{
					{
						Name: "http",
						Port: int32(80),
						TargetPort: intstr.IntOrString{
							Type:   intstr.Int,
							IntVal: 8080,
						},
					},
				},
			},
		}

		for _, nodeIP := range additionalNodeNetworkIPs {
			err = utils.RunPingFromPodWithTimeoutLimit(ctx, lbTestPodName, testNamespace, nodeIP, pingTimeoutSeconds)
			Expect(err).NotTo(HaveOccurred())
		}

		err = utils.CreateNodeportService(ctx, cl, &svc)
		Expect(err).NotTo(HaveOccurred())

		err = utils.WaitForServiceReadiness(ctx, cl, svcName, testNamespace, corev1.ServiceTypeLoadBalancer)
		Expect(err).NotTo(HaveOccurred())

		err = utils.TestLoadBalancerService(ctx, cl, svcName, testNamespace, 80)
		Expect(err).NotTo(HaveOccurred())

		klog.Infof("Successfully tested behaviour for L2 multinetwork LoadBalancer service")

		cleanup()
		err = utils.WaitForPodDeletion(ctx, cl, lbTestPodName, testNamespace)
		Expect(err).ToNot(HaveOccurred())

		// delete multinetwork LoadBalancer service
		err = utils.DeleteIfExists(ctx, cl, &svc, "service")
		Expect(err).NotTo(HaveOccurred())
	})

	AfterAll(func() {
		kubeconfig := os.Getenv("KUBECONFIG")
		c, err = client.NewClientSet(kubeconfig)
		Expect(err).NotTo(HaveOccurred())

		config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
		Expect(err).NotTo(HaveOccurred())

		nc, err = createNetworkClient(config)
		Expect(err).NotTo(HaveOccurred())

		err = c.CoreV1().Pods(testNamespace).DeleteCollection(ctx, metav1.DeleteOptions{}, metav1.ListOptions{})
		Expect(err).NotTo(HaveOccurred())
		err = network.TeardownNetwork(ctx, nc, additionalNetworkName)
		Expect(err).NotTo(HaveOccurred())
	})

})

func createDynamicClient(config *rest.Config) (*dynamic.DynamicClient, error) {
	dynamicClient, err := dynamic.NewForConfig(config)
	if err != nil {
		clientErr := fmt.Errorf("Failed to create config for test custer network client: %v", err)
		klog.Error(clientErr)
		return nil, clientErr
	}
	klog.Info("New dynamic client created.")
	return dynamicClient, nil
}

func createNetworkClient(config *rest.Config) (*networkclientset.Clientset, error) {
	networkClient, err := networkclientset.NewForConfig(config)
	if err != nil {
		clientErr := fmt.Errorf("Failed to create config for test custer network client: %v", err)
		klog.Error(clientErr)
		return nil, clientErr
	}
	klog.Info("New network client created.")
	return networkClient, nil
}

func createWorkloadPodOnEachNode(c client.Interface, ctx context.Context, additionalNetworkNodePoolName string, additionalNetworkName string, podInterfaceName string, testNamespace string) error {
	allNodes, err := c.CoreV1().Nodes().List(ctx, metav1.ListOptions{LabelSelector: fmt.Sprintf("%s=%s", nodeSelectorKey, additionalNetworkNodePoolName)})
	if err != nil {
		klog.Error("Failed to list nodes: %v", err)
		return err
	}
	for i, node := range allNodes.Items {
		podName := fmt.Sprintf("multinetworkpod-%d", i)
		_, err := network.CreateMultiNetworkPodOnNode(ctx, c, testNamespace, podName, node.Name, map[string]string{additionalNetworkName: podInterfaceName})
		if err != nil {
			klog.Error("failed to created pod(%s)", podName, err)
			return err
		}
	}
	return nil
}
