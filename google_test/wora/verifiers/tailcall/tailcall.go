package tailcall

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"gke-internal.googlesource.com/anthos-networking/test-infra/pkg/network"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/utils/ptr"

	k8sv1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	networkv1 "k8s.io/cloud-provider-gcp/crd/apis/network/v1"

	"k8s.io/client-go/tools/remotecommand"

	"gke-internal.googlesource.com/anthos-networking/test-infra/pkg/client"
	networkclientset "k8s.io/cloud-provider-gcp/crd/client/network/clientset/versioned"
)

const (
	anetdLabelSelectorLabel = "k8s-app=cilium"
	vlanNetworkName         = "vlan100"
	mgtNetworkName          = "mgmt-network"
)

var (
	vlanNetwork = networkv1.Network{
		ObjectMeta: metav1.ObjectMeta{
			Name: vlanNetworkName,
		},
		Spec: networkv1.NetworkSpec{
			Type: "L2",
			NodeInterfaceMatcher: networkv1.NodeInterfaceMatcher{
				InterfaceName: ptr.To("vxlan0"),
			},
			DNSConfig: &networkv1.DNSConfig{
				Nameservers: []string{"0.0.0.0"},
			},
			Gateway4: ptr.To("10.128.0.1"),
			L2NetworkConfig: &networkv1.L2NetworkConfig{
				VlanID: ptr.To(int32(100)),
			},
			Routes: []networkv1.Route{{To: "10.240.0.0/13"}, {To: "172.26.0.0/16"}},
		},
	}
)

var _ = Describe("Verifiers/TailCall", Label("tailcall"), Ordered, func() {
	var c client.Interface
	var err error

	kubeconfig := os.Getenv("KUBECONFIG")
	c, err = client.NewClientSet(kubeconfig)
	Expect(err).NotTo(HaveOccurred())

	config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	Expect(err).NotTo(HaveOccurred())

	nc, err := networkclientset.NewForConfig(config)
	Expect(err).NotTo(HaveOccurred())

	BeforeAll(func() {
		// Create the Network object
		_, err = network.CreateNetwork(context.Background(), nc, &vlanNetwork)
		Expect(err).NotTo(HaveOccurred(), fmt.Sprintf("Failed to create network: %s", vlanNetworkName))

		DeferCleanup(func() {
			err = network.TeardownNetwork(context.Background(), nc, vlanNetworkName)
			Expect(err).NotTo(HaveOccurred(), fmt.Sprintf("Failed to delete network: %s", vlanNetworkName))
		})
	})

	It("Verifies BPF tail calls are loaded on vlan and mgmt networks", func() {
		anetdPods, err := c.CoreV1().Pods("kube-system").List(context.Background(), metav1.ListOptions{LabelSelector: anetdLabelSelectorLabel})
		Expect(err).NotTo(HaveOccurred())

		// anetd needs some time to reconcile the networks
		Eventually(func() bool {
			for _, anetdPod := range anetdPods.Items {
				// Check both interfaces and both directions
				if !checkInterfacesLoaded(c, config, anetdPod, "vxlan0.100", "ingress") ||
					!checkInterfacesLoaded(c, config, anetdPod, "vxlan0.100", "egress") {
					return false
				}
			}
			return true
		}).WithTimeout(5*time.Second).Should(BeTrue(), "Timed out waiting for anetd to reconcile the networks")

		for _, anetdPod := range anetdPods.Items {
			validateTailCallMap(c, config, anetdPod, []string{"vxlan0.100", "vxlan0"})
		}
	})
})

// checkInterfacesLoaded checks if a specific interface and direction is loaded
func checkInterfacesLoaded(c client.Interface, config *rest.Config, pod k8sv1.Pod, iface, direction string) bool {
	command := []string{"tc", "filter", "show", "dev", iface, direction}
	stdout, _, err := execCommandInPod(c, config, pod.GetName(), pod.GetNamespace(), command)
	if err != nil || !strings.Contains(stdout, "filter protocol all pref") {
		return false
	}
	return true
}

func validateTailCallMap(c client.Interface, config *rest.Config, pod k8sv1.Pod, interfaces []string) {
	podName := pod.GetName()
	ns := pod.GetNamespace()
	for _, iface := range interfaces {
		for _, direction := range []string{"ingress", "egress"} {
			// Verifying tc filter for the given direction
			command := []string{"tc", "filter", "show", "dev", iface, direction}
			stdout, stderr, err := execCommandInPod(c, config, podName, ns, command)
			Expect(err).NotTo(HaveOccurred(), fmt.Sprintf("Failed to execute bpftool command: %s", stderr))
			Expect(stdout).To(ContainSubstring("filter protocol all pref"), formatErrorMessage(podName, iface, direction, "tc filter did not show any ebpf program loaded"))

			// Extract program ID from the `tc` output
			progID := extractProgID(stdout)
			Expect(progID).NotTo(BeEmpty(), formatErrorMessage(podName, iface, direction, "No program ID found in tc filter output"))

			// Verifying bpftool prog show
			command = []string{"bpftool", "prog", "show", "id", progID}
			stdout, stderr, err = execCommandInPod(c, config, podName, ns, command)
			Expect(err).NotTo(HaveOccurred(), fmt.Sprintf("Failed to execute bpftool command: %s", stderr))
			Expect(stdout).To(ContainSubstring("map_ids"), formatErrorMessage(podName, iface, direction, "bpftool prog show did not show any maps loaded"))

			// Extracting and verifying map dumps
			mapIDs := extractMapIDs(stdout)
			Expect(mapIDs).NotTo(BeEmpty(), "No map IDs found in bpftool prog show output")

			mapFound := false
			for _, mapID := range mapIDs {
				command = []string{"bpftool", "map", "show", "id", mapID}
				stdout, stderr, err = execCommandInPod(c, config, podName, ns, command)
				Expect(err).NotTo(HaveOccurred(), fmt.Sprintf("Failed to execute bpftool command: %s", stderr))

				if !strings.Contains(stdout, "name cilium_calls_") {
					continue
				}

				mapFound = true

				command = []string{"bpftool", "map", "dump", "id", mapID}
				stdout, stderr, err = execCommandInPod(c, config, podName, ns, command)
				Expect(err).NotTo(HaveOccurred(), fmt.Sprintf("Failed to execute bpftool command: %s", stderr))
				Expect(stdout).NotTo(ContainSubstring("Found 0 elements"), formatErrorMessage(podName, iface, direction, fmt.Sprintf("bpftool map dump for map ID %s found 0 elements", mapID)))
			}
			Expect(mapFound).To(BeTrue(), formatErrorMessage(podName, iface, direction, "cilium_calls_ map is not found"))
		}
	}
}

func formatErrorMessage(podName, iface, direction, specificMessage string) string {
	return fmt.Sprintf("Error in pod %s, interface %s, direction %s: %s", podName, iface, direction, specificMessage)
}

func execCommandInPod(c client.Interface, config *rest.Config, podName, namespace string, command []string) (string, string, error) {
	req := c.CoreV1().RESTClient().Post().
		Resource("pods").
		Name(podName).
		Namespace(namespace).
		SubResource("exec").
		Param("container", "cilium-agent")

	req.VersionedParams(&k8sv1.PodExecOptions{
		Container: "cilium-agent",
		Command:   command,
		Stdin:     false,
		Stdout:    true,
		Stderr:    true,
		TTY:       false,
	}, scheme.ParameterCodec)

	exec, err := remotecommand.NewSPDYExecutor(config, "POST", req.URL())
	if err != nil {
		return "", "", err
	}

	var stdout, stderr strings.Builder
	err = exec.Stream(remotecommand.StreamOptions{
		Stdout: &stdout,
		Stderr: &stderr,
	})

	return stdout.String(), stderr.String(), err
}

// extractProgID extracts the program ID from the tc filter output
func extractProgID(output string) string {
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		if strings.Contains(line, "id") {
			// Extract the ID following "id"
			parts := strings.Fields(line)
			for i, part := range parts {
				if part == "id" && i+1 < len(parts) {
					return parts[i+1]
				}
			}
		}
	}
	return ""
}

// extractMapIDs extracts map IDs from bpftool prog show output
func extractMapIDs(output string) []string {
	var mapIDs []string
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		if strings.Contains(line, "map_ids") {
			// Extract the IDs following "map_ids"
			parts := strings.Fields(line)
			for i, part := range parts {
				if part == "map_ids" && i+1 < len(parts) {
					ids := strings.Split(parts[i+1], ",")
					mapIDs = append(mapIDs, ids...)
				}
			}
		}
	}
	return mapIDs
}
