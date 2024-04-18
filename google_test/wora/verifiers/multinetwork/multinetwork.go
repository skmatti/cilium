package multinetwork

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	networkv1 "k8s.io/cloud-provider-gcp/crd/apis/network/v1"
	networkclientset "k8s.io/cloud-provider-gcp/crd/client/network/clientset/versioned"

	"gke-internal.googlesource.com/anthos-networking/test-infra/pkg/client"
	klog "gke-internal.googlesource.com/syllogi/sanitized-klog"

	"gke-internal.googlesource.com/anthos-networking/test-infra/pkg/artifact"
	"gke-internal.googlesource.com/anthos-networking/test-infra/pkg/network"
)

const (
	additionalNetworkName         = "vlan-test"
	clusterCIDRConfigName         = "ccc-test"
	podInterfaceName              = "eth1"
	nodeSelectorKey               = "baremetal.cluster.gke.io/node-pool"
	additionalNetworkNodePoolName = "np1"
	maskSizeForAllNodesCombined   = 27
	testNamespace                 = "default"
)

var _ = Describe("Verifiers/multinetwork", Label("multinetwork"), Ordered, func() {
	var (
		c                 client.Interface
		dc                *dynamic.DynamicClient
		nc                *networkclientset.Clientset
		err               error
		nodeInterfaceName = "ens224"
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

		hercEnvJsonFilePath := filepath.Join(filepath.Dir(kubeconfig), "herc_env.json")
		Expect(hercEnvJsonFilePath).NotTo(BeEmpty())
		Expect(filepath.IsAbs(hercEnvJsonFilePath)).To(BeTrue())
		additionalNodeNetworkInfo, err := artifact.ExtractNodeNetworkInfo(hercEnvJsonFilePath)
		Expect(err).NotTo(HaveOccurred())

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

		_, podIPv4cidr, _ := net.ParseCIDR(fmt.Sprintf("%s/%d", additionalNodeNetworkInfo.GatewayServer, maskSizeForAllNodesCombined))
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
		err = network.ValidateMultiNetworkPodConnectivityFromEachNode(ctx, nc, c, dc, testNamespace, additionalNetworkName, podInterfaceName, allTestWorkloadPods, allNodes)
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
	for _, node := range allNodes.Items {
		podName := fmt.Sprintf("multinetworkpod-%s", node.Name)
		_, err := network.CreateMultiNetworkPodOnNode(ctx, c, testNamespace, podName, node.Name, map[string]string{additionalNetworkName: podInterfaceName})
		if err != nil {
			klog.Error("failed to created pod(%s)", podName, err)
			return err
		}
	}
	return nil
}
