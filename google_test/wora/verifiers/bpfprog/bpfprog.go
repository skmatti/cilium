package bpfprog

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time" // Do not use pkg/time in test code.

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	klog "gke-internal.googlesource.com/syllogi/sanitized-klog"
	e2escheme "gke-internal.googlesource.com/third_party/cilium/google_test/wora/e2e/pkg/test/scheme"
	"gke-internal.googlesource.com/third_party/cilium/google_test/wora/e2e/pkg/test/utils"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	k8sclient "sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	anetdLabelSelectorLabel        = "k8s-app=cilium"
	anetOperatorLabelSelectorLabel = "io.cilium/app=operator"
	anetdNamespace                 = "kube-system"
	verifierErrorInLog             = "Verifier error"
	compilationErrorInLog          = "Failed to compile"
)

var _ = Describe("Verifiers/BPFProg", Label("bpfprog"), func() {
	var clientset *kubernetes.Clientset
	var cl k8sclient.Client
	var err error
	var ctx context.Context

	BeforeEach(func() {
		s := e2escheme.Scheme()
		ctx, _ = context.WithTimeout(context.Background(), 10*time.Minute)
		kubeconfig := os.Getenv("KUBECONFIG")
		config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
		Expect(err).NotTo(HaveOccurred())

		clientset, err = kubernetes.NewForConfig(config)
		Expect(err).NotTo(HaveOccurred(), "Failed to create Kubernetes clientset")

		cl, err = k8sclient.New(config, k8sclient.Options{Scheme: s})
		Expect(err).NotTo(HaveOccurred())
		ctx, _ = context.WithTimeout(context.Background(), 10*time.Minute)
	})

	Describe("StatusOfCilium", func() {
		var anetdPods *corev1.PodList

		BeforeEach(func() {
			anetdPods, err = clientset.CoreV1().Pods(anetdNamespace).List(context.Background(), metav1.ListOptions{LabelSelector: anetdLabelSelectorLabel})
			Expect(err).NotTo(HaveOccurred())
		})

		It("eBPF programs are attached properly", func() {
			for _, anetdPod := range anetdPods.Items {
				// Only check on nodes where anetd is ready, since we need to use the bpftool
				// installed inside anetd.
				for _, condition := range anetdPod.Status.Conditions {
					if condition.Type == corev1.PodReady {
						if condition.Status != corev1.ConditionTrue {
							return
						}
					}
				}

				excluded, err := isEth0Excluded(ctx, cl)
				Expect(err).NotTo(HaveOccurred(), "Failed to validate 'device-prefixes-to-exclude' config")

				if !excluded {
					klog.Infof("Skipping test because device-prefixes-to-exclude is not set")
				} else {
					By("No eBPF program should be installed on eth0 on " + anetdPod.GetName())
					hasNetDev, err := checkEBPFProgramInstallation(anetdPod.GetName(), anetdNamespace, "eth0", "netdev")
					Expect(err).NotTo(HaveOccurred())
					Expect(hasNetDev).To(BeFalse(), `No netdev program should be installed on eth0.`)
				}

				By("eBPF program should be installed on vxlan0 on " + anetdPod.GetName())
				hasNetDevIngress, err := checkEBPFProgramInstallation(anetdPod.GetName(), anetdNamespace, "vxlan0", "cil_from_netdev-vxlan0")
				Expect(err).NotTo(HaveOccurred())
				Expect(hasNetDevIngress).To(BeTrue(), "eBPF program should be installed on vxlan0 ingress")
				By("eBPF program should be installed on vxlan0 on " + anetdPod.GetName())
				hasNetDevEgress, err := checkEBPFProgramInstallation(anetdPod.GetName(), anetdNamespace, "vxlan0", "cil_to_netdev-vxlan0")
				Expect(err).NotTo(HaveOccurred())
				Expect(hasNetDevEgress).To(BeTrue(), "eBPF program should be installed on vxlan0 ingress")
			}
		})
	})
})

func checkEBPFProgramInstallation(podName, podNs, interfaceName, programName string) (bool, error) {
	cmd := exec.Command("kubectl",
		"exec",
		podName,
		"-n", podNs,
		"--",
		// Use bpftool here instead of 'tc filter' so that it's also compatible with tcx.
		"bpftool", "net", "show", "dev", interfaceName,
	)
	outBytes, err := cmd.CombinedOutput()
	if err != nil {
		return false, fmt.Errorf("failed to execute kubectl command: %v", err)
	}
	out := string(outBytes)
	klog.Infof("bpf programm detected on %s: %s", interfaceName, out)
	return strings.Contains(out, programName), nil
}

func isEth0Excluded(ctx context.Context, cl k8sclient.Client) (bool, error) {
	return utils.ValidateCiliumConfigFlag(ctx, cl, []utils.CiliumConfig{
		{
			Key:   "device-prefixes-to-exclude",
			Value: "eth0",
		},
	})
}
