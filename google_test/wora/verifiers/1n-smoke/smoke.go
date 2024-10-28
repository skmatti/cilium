package smoke

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"math/rand"
	"net"
	"os"
	"regexp"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/utils/ptr"

	"gke-internal.googlesource.com/anthos-networking/test-infra/pkg/client"
)

const defaultTimeout time.Duration = 30 * time.Minute
const defaultPolling time.Duration = 30 * time.Second
const testNS = "default"
const ciliumNS = "kube-system"

var config = kontrollerConfig{
	projectID:  "anthos-networking-ci",
	projectNum: "1076491969837",
	mesh:       fmt.Sprintf("wora-mesh-%0x", rand.Int63()&0xffff),

	registry: "gke-release-staging",
	tag:      "v0.0.112",
}

func init() {
	flag.StringVar(&config.projectID, "project-id", config.projectID, "GCP project ID")
	flag.StringVar(&config.projectNum, "project-num", config.projectNum, "GCP project NUM")
	flag.StringVar(&config.mesh, "mesh", config.mesh, "mesh")
}

var c client.Interface

var zones []string

var _ = BeforeSuite(func(ctx context.Context) {
	if !Label("1n").MatchesLabelFilter(GinkgoLabelFilter()) {
		GinkgoWriter.Println("skipping: label 1n not matched")
		return
	}
	Expect(config.mesh).ToNot(BeEmpty(), "mesh name must be provided")

	var err error
	kubeconfig := os.Getenv("KUBECONFIG")
	Expect(kubeconfig).ToNot(BeEmpty(), "KUBECONFIG env variable must be set")
	c, err = client.NewClientSet(kubeconfig)
	Expect(err).NotTo(HaveOccurred())

	Eventually(func() error {
		return daemonsetReady(ctx, c, ciliumNS, "anetd")
	}).WithTimeout(5*time.Minute).WithPolling(defaultPolling).
		Should(Succeed(), "Confirm ds/anetd is healthy")

	By("updating cilium-config-emergency-override")
	cm := &corev1.ConfigMap{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "v1",
			Kind:       "ConfigMap",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "cilium-config-emergency-override",
			Namespace: ciliumNS,
		},
		Data: map[string]string{
			"traffic-director-mesh":    config.mesh,
			"enable-enhanced-services": "true",
			"debug":                    "true",
		},
	}
	cmPatch, err := json.Marshal(cm)
	Expect(err).NotTo(HaveOccurred())
	_, err = c.CoreV1().ConfigMaps(cm.Namespace).Patch(ctx, cm.Name, types.ApplyPatchType, cmPatch, metav1.PatchOptions{
		Force:        ptr.To[bool](true),
		FieldManager: "wora",
	})
	Expect(err).NotTo(HaveOccurred())

	By("creating mesh")
	Eventually(func(g Gomega) {
		createMeshPod := "gcloud-create-mesh"
		deletePod(ctx, c, testNS, createMeshPod)
		createMeshCmd := fmt.Sprintf(`gcloud network-services meshes describe %s --location global || {
			echo name: %s > mesh.yaml;
			gcloud network-services meshes import --source mesh.yaml --location global %s;
		}`, config.mesh, config.mesh, config.mesh)
		err = createGcloudPod(ctx, c, createMeshPod, createMeshCmd)
		g.Expect(err).NotTo(HaveOccurred())
		g.Eventually(func() error {
			return podDone(ctx, c, testNS, createMeshPod)
		}).WithTimeout(5 * time.Minute).WithPolling(defaultPolling).Should(Succeed())
		err = deletePod(ctx, c, testNS, createMeshPod)
		g.Expect(err).NotTo(HaveOccurred())
	}).WithTimeout(10 * time.Minute).WithPolling(defaultPolling).Should(Succeed())

	By("deleting old kontroller and service (if any)")
	deleteKontroller(ctx, c)
	deleteTestService(ctx, c)

	By("creating new kontroller")
	err = installKontroller(ctx, c, config)
	Expect(err).NotTo(HaveOccurred())

	By("waiting for kontroller to become ready")
	Eventually(func() error {
		return kontrollerReady(ctx, c)
	}).WithTimeout(2 * time.Minute).WithPolling(defaultPolling).Should(Succeed())

	By("creating firewall rule")
	Eventually(func(g Gomega) {
		createFirewallPod := "gcloud-create-firewall"
		deletePod(ctx, c, testNS, createFirewallPod)
		sourceRanges := strings.Join([]string{"130.211.0.0/22", "35.191.0.0/16", "209.85.152.0/22", "209.85.204.0/22"}, ",")
		delete := fmt.Sprintf("gcloud compute --project=%s firewall-rules delete %s --quiet",
			config.projectID,
			firewallRuleName(config.mesh),
		)
		create := fmt.Sprintf("gcloud compute --project=%s firewall-rules create %s  --direction=INGRESS --priority=1000 --network=default --action=ALLOW --rules=all --source-ranges=%s",
			config.projectID,
			firewallRuleName(config.mesh),
			sourceRanges,
		)
		createFirewallCmd := fmt.Sprintf("%s; %s", delete, create) // Creating an exising firewall-rule would fail, so we first delete.
		err = createGcloudPod(ctx, c, createFirewallPod, createFirewallCmd)
		g.Expect(err).NotTo(HaveOccurred())
		g.Eventually(func() error {
			return podDone(ctx, c, testNS, createFirewallPod)
		}).WithTimeout(5 * time.Minute).WithPolling(defaultPolling).Should(Succeed())
		err = deletePod(ctx, c, testNS, createFirewallPod)
		g.Expect(err).NotTo(HaveOccurred())
	}).WithTimeout(10 * time.Minute).WithPolling(defaultPolling).Should(Succeed())
}, NodeTimeout(defaultTimeout))

var _ = AfterSuite(func(ctx context.Context) {
	if !Label("1n").MatchesLabelFilter(GinkgoLabelFilter()) {
		GinkgoWriter.Println("skipping: label 1n not matched")
		return
	}
	deleteTestService(ctx, c)

	By("deleting firewall")
	Eventually(func(g Gomega) {
		deleteFirewallPod := "gcloud-delete-firewall"
		deletePod(ctx, c, testNS, deleteFirewallPod)
		deleteFirewallCmd := fmt.Sprintf("gcloud compute --project=%s firewall-rules delete %s --quiet",
			config.projectID,
			firewallRuleName(config.mesh),
		)
		err := createGcloudPod(ctx, c, deleteFirewallPod, deleteFirewallCmd)
		g.Expect(err).NotTo(HaveOccurred())
		g.Eventually(func() error {
			return podDone(ctx, c, testNS, deleteFirewallPod)
		}).WithTimeout(5 * time.Minute).WithPolling(defaultPolling).Should(Succeed())
		deletePod(ctx, c, testNS, deleteFirewallPod)
	}).WithTimeout(10 * time.Minute).WithPolling(defaultPolling).Should(Succeed())

	By("deleting mesh")
	Eventually(func(g Gomega) {
		deleteMeshPod := "gcloud-delete-mesh"
		deletePod(ctx, c, testNS, deleteMeshPod)
		deleteMeshCmd := fmt.Sprintf("gcloud network-services meshes delete --location global --quiet %s", config.mesh)

		err := createGcloudPod(ctx, c, deleteMeshPod, deleteMeshCmd)
		g.Expect(err).NotTo(HaveOccurred())

		g.Eventually(func() error {
			return podDone(ctx, c, testNS, deleteMeshPod)
		}).WithTimeout(2 * time.Minute).WithPolling(defaultPolling).Should(Succeed())

		deletePod(ctx, c, testNS, deleteMeshPod)
	}).WithTimeout(5 * time.Minute).WithPolling(defaultPolling).Should(Succeed())
}, NodeTimeout(defaultTimeout))

var _ = Describe("Verifiers/1N", Label("1n"), func() {
	It("observes events of related services", func(ctx context.Context) {
		By("ensuring the environment is clean")
		err := deleteTestService(ctx, c)
		if err == nil {
			waitKontrollerServiceDelete(Default, ctx, c)
		}

		By("restarting anetd agents")
		Eventually(func(g Gomega) {
			pods, err := c.CoreV1().Pods(ciliumNS).List(ctx, metav1.ListOptions{
				LabelSelector: "k8s-app=cilium",
			})
			g.Expect(err).ToNot(HaveOccurred())
			g.Expect(pods.Items).ToNot(BeEmpty())

			for _, pod := range pods.Items {
				if !strings.HasPrefix(pod.Name, "anetd") {
					continue
				}
				c.CoreV1().Pods(ciliumNS).Delete(ctx, pod.Name, metav1.DeleteOptions{})
			}
		}).WithTimeout(2 * time.Minute).WithPolling(time.Minute).Should(Succeed())

		By("waiting for anetd agents to become ready")
		Eventually(func() error {
			return daemonsetReady(ctx, c, ciliumNS, "anetd")
		}).WithTimeout(5 * time.Minute).WithPolling(defaultPolling).Should(Succeed())

		By("waiting for kontroller to become ready")
		Eventually(func() error {
			return kontrollerReady(ctx, c)
		}).WithTimeout(5 * time.Minute).WithPolling(defaultPolling).Should(Succeed())

		By("creating 1N service")
		Eventually(func(g Gomega) {
			err := deleteTestService(ctx, c)
			if err == nil {
				waitKontrollerServiceDelete(g, ctx, c)
			}

			err = createTestServiceWithNEGs(ctx, c)
			g.Expect(err).NotTo(HaveOccurred())

			g.Eventually(func() error {
				return testServiceReady(ctx, c)
			}).WithTimeout(2 * time.Minute).WithPolling(defaultPolling).Should(Succeed())

			waitKontrollerServiceUpdate(g, ctx, c)
		}).WithTimeout(20 * time.Minute).WithPolling(defaultPolling).Should(Succeed())

		By("verifying the latency to propagate the events")
		var anetdIPs []string
		Eventually(func() (err error) {
			anetdIPs, err = getAnetdIP(ctx, c)
			return err
		}).WithTimeout(2 * time.Minute).WithPolling(defaultPolling).Should(Succeed())

		var latencies map[string]map[string]latency
		Eventually(func(g Gomega) {
			metrics := getAnetdMetrics(g, ctx, c, anetdIPs)

			lines := strings.Split(metrics, "\n")
			var err error
			latencies, err = getLatency(lines)
			g.Expect(err).NotTo(HaveOccurred())
			// TODO(b/345443951): Re-enable test for service latency
			// In WORA/anthos-networking-ci project it shows up as skipped/lost event.
			//g.Expect(latencies["service"]["add"].count).ToNot(BeZero())
			g.Expect(latencies["port"]["add"].count).ToNot(BeZero())
			g.Expect(latencies["endpoint"]["add"].count).ToNot(BeZero())
		}).WithTimeout(5 * time.Minute).WithPolling(defaultPolling).Should(Succeed())

		// TODO(b/345443951): Remove the check
		if lat, ok := latencies["service"]["add"]; ok {
			GinkgoWriter.Println("service:\t", lat.String())
		}
		GinkgoWriter.Println("port:\t\t", latencies["port"]["add"].String())
		GinkgoWriter.Println("endpoint:\t", latencies["endpoint"]["add"].String())

		//Expect(latencies["service"]["add"].avg()).To(BeNumerically("<=", 600))
		Expect(latencies["port"]["add"].avg()).To(BeNumerically("<=", 600))
		Expect(latencies["endpoint"]["add"].avg()).To(BeNumerically("<=", 600))

		By("making sure related resources were cleaned up")
		err = deleteTestService(ctx, c)
		Expect(err).NotTo(HaveOccurred())
		waitKontrollerServiceDelete(Default, ctx, c)
	}, NodeTimeout(defaultTimeout), FlakeAttempts(3))
})

func getAnetdMetrics(g Gomega, ctx context.Context, c kubernetes.Interface, anetdIPs []string) string {
	attempt := 1
	var metrics string
	g.Eventually(func(g Gomega) {
		url := fmt.Sprintf("http://%s/metrics", net.JoinHostPort(anetdIPs[attempt%len(anetdIPs)], "9990"))
		curlPodName := fmt.Sprintf("curl-test-%.2d-%s",
			attempt, strings.ToLower(base64.RawURLEncoding.EncodeToString([]byte(url))))
		attempt++

		err := createCurlPod(ctx, c, curlPodName, url)
		g.Expect(err).NotTo(HaveOccurred())
		g.Eventually(func() error {
			return podDone(ctx, c, testNS, curlPodName)
		}).WithTimeout(2 * time.Minute).WithPolling(defaultPolling).Should(Succeed())

		metrics, err = getPodLogs(ctx, c, testNS, curlPodName)
		g.Expect(err).NotTo(HaveOccurred())

		err = deletePod(ctx, c, testNS, curlPodName)
		g.Expect(err).NotTo(HaveOccurred())

		g.Expect(metrics).To(ContainSubstring("cilium_google_1n_hybrid_cache"))
	}).WithTimeout(5 * time.Minute).WithPolling(defaultPolling).Should(Succeed())
	return metrics
}

func waitKontrollerServiceDelete(g Gomega, ctx context.Context, kc kubernetes.Interface) {
	waitKontrollerServiceOp(g, ctx, kc, "delete")
}

func waitKontrollerServiceUpdate(g Gomega, ctx context.Context, kc kubernetes.Interface) {
	waitKontrollerServiceOp(g, ctx, kc, "update")
}

func waitKontrollerServiceOp(g Gomega, ctx context.Context, kc kubernetes.Interface, op string) {
	g.Eventually(func(g Gomega) {
		name, err := getPodName(ctx, c, kontrollerNamespace, "app=kontroller")
		g.Expect(err).NotTo(HaveOccurred())

		logs, err := getPodLogs(ctx, c, kontrollerNamespace, name)
		g.Expect(err).NotTo(HaveOccurred())

		g.Expect(logs).To(ContainSubstring(op + "Start"))
		// Analyze only the newest logs
		suffix := strings.Split(logs, op+"Start")
		lines := strings.Split(suffix[len(suffix)-1], "\n")
		g.Expect(lines).To(ContainElement(ContainSubstring(op + "End")))
	}).WithTimeout(10 * time.Minute).WithPolling(defaultPolling).Should(Succeed())
}

func createGcloudPod(ctx context.Context, kc kubernetes.Interface, name, cmd string) error {
	pod := &corev1.Pod{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "v1",
			Kind:       "Pod",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: testNS,
		},
		Spec: corev1.PodSpec{
			HostNetwork:   true,
			RestartPolicy: corev1.RestartPolicyNever,
			Containers: []corev1.Container{
				{
					Name:  "gcloud",
					Image: "gcr.io/google.com/cloudsdktool/google-cloud-cli",
					Args:  []string{"sh", "-c", cmd},
				},
			},
		},
	}
	_, err := kc.CoreV1().Pods(testNS).Create(ctx, pod, metav1.CreateOptions{})
	return err
}

func createCurlPod(ctx context.Context, kc kubernetes.Interface, name, url string) error {
	pod := &corev1.Pod{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "v1",
			Kind:       "Pod",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: testNS,
		},
		Spec: corev1.PodSpec{
			RestartPolicy: corev1.RestartPolicyOnFailure,
			Containers: []corev1.Container{
				{
					Image: "curlimages/curl",
					Name:  "curl",
					Args:  []string{"curl", "--no-progress-meter", url},
				},
			},
		},
	}
	_, err := kc.CoreV1().Pods(testNS).Create(ctx, pod, metav1.CreateOptions{})
	return err
}

type latency struct {
	sum, count float64
}

func (l latency) avg() float64 {
	if l.count == 0 {
		return 0
	}
	return l.sum / l.count
}

func (l latency) String() string {
	return fmt.Sprintf("sum: %.0f, count: %.0f, avg: %.2f", l.sum, l.count, l.avg())
}

var latencyMetric = regexp.MustCompile(`cilium_google_1n_hybrid_cache_kubeapi_td_propagation_differences_seconds_(sum|count){event="(add|update|delete)",resource="(service|port|endpoint)"}`)

func getLatency(metrics []string) (map[string]map[string]latency, error) {
	ret := map[string]map[string]latency{
		"service":  {},
		"port":     {},
		"endpoint": {},
	}
	for _, line := range metrics {
		if !strings.HasPrefix(line, "cilium_google_1n_hybrid_cache_kubeapi_td_propagation_differences_seconds") {
			continue
		}
		subs := latencyMetric.FindStringSubmatch(line)
		if subs == nil {
			continue
		}
		var val float64
		_, after, _ := strings.Cut(line, " ")
		_, err := fmt.Sscanf(after, "%f", &val)
		if err != nil {
			return nil, err
		}
		lat := ret[subs[3]][subs[2]]
		switch subs[1] {
		case "sum":
			lat.sum = val
		case "count":
			lat.count = val
		}
		ret[subs[3]][subs[2]] = lat
	}
	return ret, nil
}
