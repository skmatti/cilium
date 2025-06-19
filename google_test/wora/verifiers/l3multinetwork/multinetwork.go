package l3multinetwork

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"time" // Do not use pkg/time in test code.

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	e2escheme "gke-internal.googlesource.com/third_party/cilium/google_test/wora/e2e/pkg/test/scheme"
	"gke-internal.googlesource.com/third_party/cilium/google_test/wora/e2e/pkg/test/utils"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	k8sclient "sigs.k8s.io/controller-runtime/pkg/client"

	networkv1 "github.com/GoogleCloudPlatform/gke-networking-api/apis/network/v1"
	networkclientset "github.com/GoogleCloudPlatform/gke-networking-api/client/network/clientset/versioned"

	ipamv1 "gke-internal.googlesource.com/anthos-networking/ipam-controller/api/v1alpha1"
	klog "gke-internal.googlesource.com/syllogi/sanitized-klog"

	"gke-internal.googlesource.com/anthos-networking/test-infra/pkg/client"
	"gke-internal.googlesource.com/anthos-networking/test-infra/pkg/network"
)

const (
	additionalNetworkName         = "vlanl3"
	clusterCIDRConfigName         = "cccl3"
	podInterfaceName              = "eth1"
	nodeSelectorKey               = "baremetal.cluster.gke.io/node-pool"
	additionalNetworkNodePoolName = "np1"
	maskSizeForAllNodesCombined   = 27
	nwSelectorKey                 = "networking.gke.io/network"
	testNamespace                 = "default"
	// cleanupPods sets the default value of whether the deployed test pod will be
	// deleted after test finish. Here true means the test pod will be cleaned up
	// after the test run.
	cleanupPods        = true
	hostNetworkPodName = "host-nw-pod"
	podsTimeout        = 30 * time.Minute
)

var _ = Describe("Verifiers/l3multinetwork", Label("l3multinetwork"), Ordered, func() {
	var (
		c                 client.Interface
		cl                k8sclient.Client
		ctx               context.Context
		dc                *dynamic.DynamicClient
		nc                *networkclientset.Clientset
		err               error
		nodeInterfaceName string
		cidr              string
	)

	BeforeAll(func() {
		ctx = context.Background()
		s := e2escheme.Scheme()

		kubeconfig := os.Getenv("KUBECONFIG")
		c, err = client.NewClientSet(kubeconfig)
		Expect(err).NotTo(HaveOccurred())

		config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
		Expect(err).NotTo(HaveOccurred())

		cl, err = k8sclient.New(config, k8sclient.Options{Scheme: s})
		Expect(err).NotTo(HaveOccurred())

		dc, err = createDynamicClient(config)
		Expect(err).NotTo(HaveOccurred())

		nc, err = createNetworkClient(config)
		Expect(err).NotTo(HaveOccurred())

		scheme := e2escheme.Scheme()
		// create a controller runtime client
		cl, err = k8sclient.New(config, k8sclient.Options{Scheme: scheme})
		Expect(err).NotTo(HaveOccurred())

		// GDC-SO on GCE nodes are brought up with 3 node interfaces:
		// vxlan0 (default network) (range: )
		// vxlan1 (additional node network 1) (range: 10.100.0.0/21)
		// vxlan2 (additional node network 2) (range: 10.150.0.0/21)
		// These vxlan interfaces are setup on all the GCE nodes of the cluster: worker nodes,
		// control plane nodes and bootstrapper node and act as the k8s node interfaces.

		// In this test, we create one additional pod network object with parent (node) interface
		// set to vxlan1 interface on the underlying node network.
		nodeInterfaceName = "vxlan1"
		// For L3 pod-networks, the IP range can be from any random network range
		// and different from the underlying node network's range.
		cidr = fmt.Sprintf("%s/%d", "172.168.0.1", maskSizeForAllNodesCombined)

		// Gateway of the pod-network is set to the IP of vxlan1 interface of the control plane node.
		gw4 := "10.100.0.4"

		ipamModeInternal := networkv1.InternalMode
		networkObject := networkv1.Network{
			ObjectMeta: metav1.ObjectMeta{
				Name: additionalNetworkName,
			},
			Spec: networkv1.NetworkSpec{
				Type: "L3",
				NodeInterfaceMatcher: networkv1.NodeInterfaceMatcher{
					InterfaceName: &nodeInterfaceName,
				},
				Gateway4: &gw4,
				IPAMMode: &ipamModeInternal,
				DNSConfig: &networkv1.DNSConfig{
					Nameservers: []string{"8.8.8.8"},
				},
			},
		}

		_, err = network.CreateNetwork(ctx, nc, &networkObject)
		Expect(err).NotTo(HaveOccurred())

		err = createCCCIfNotExist(ctx, cl, dc, clusterCIDRConfigName, cidr, additionalNetworkName)
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

	It("can validate reachability of multinetwork pod behind a multinetwork L3 nodeport service ", func() {
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
		_, err = utils.CreatePodWithNetworkInterfaces(ctx, cl, "nodeport-svc-test-pod", testNamespace,
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
	})

	AfterAll(func() {
		kubeconfig := os.Getenv("KUBECONFIG")
		c, err = client.NewClientSet(kubeconfig)
		Expect(err).NotTo(HaveOccurred())

		config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
		Expect(err).NotTo(HaveOccurred())

		nc, err = createNetworkClient(config)
		Expect(err).NotTo(HaveOccurred())

		ccc := &ipamv1.ClusterCIDRConfig{
			ObjectMeta: metav1.ObjectMeta{
				Name: clusterCIDRConfigName,
			},
		}
		err = utils.DeleteIfExists(ctx, cl, ccc, "ccc")
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

func createCCCIfNotExist(ctx context.Context, cl k8sclient.Client, dc *dynamic.DynamicClient, cccName, cidr, additionalNetworkName string) error {
	_, podIPv4cidr, _ := net.ParseCIDR(cidr)
	ccc := ipamv1.ClusterCIDRConfig{}
	err := cl.Get(ctx, k8sclient.ObjectKey{Name: cccName}, &ccc)
	if err == nil || !apierrors.IsNotFound(err) {
		return err
	}

	if _, err := network.CreateClusterCIDRConfig(ctx, dc, cccName, podIPv4cidr.String(), additionalNetworkName, metav1.LabelSelector{}); err != nil {
		return err
	}

	return nil
}
