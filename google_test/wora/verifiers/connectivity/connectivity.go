package connectivity

import (
	"os"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"context"

	appsv1 "k8s.io/api/apps/v1"
	k8sv1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	k8sclient "sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/spf13/afero"
	klog "gke-internal.googlesource.com/syllogi/sanitized-klog/third_party/klogv2"
	"gke-internal.googlesource.com/third_party/cilium/google_test/wora/e2e/pkg/test/utils"
)

const (
	testNamespace           = "connectivity-test"
	checkStrictEgressPolicy = true
	bootstrapperIP          = "10.200.0.1"
)

var _ = Describe("ConnectivityTest", Label("connectivity"), Ordered, func() {
	var (
		clientset *kubernetes.Clientset
		k8sClient k8sclient.Client
		config    *rest.Config
		err       error
		debugInfo *utils.DebugSuite
		ctx       context.Context
		cancel    context.CancelFunc
		debugMode bool
		namespace string
	)

	BeforeAll(func() {
		debugMode = os.Getenv("DEBUG_MODE") == "true"
		if debugMode {
			klog.Info("DEBUG_MODE is enabled. Test resources will not be cleaned up.")
		}

		ctx, cancel = context.WithCancel(context.Background())

		kubeconfig := os.Getenv("KUBECONFIG")
		Expect(kubeconfig).NotTo(BeEmpty(), "KUBECONFIG environment variable must be set")

		config, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
		Expect(err).NotTo(HaveOccurred())

		clientset, err = kubernetes.NewForConfig(config)
		Expect(err).NotTo(HaveOccurred())

		scheme := runtime.NewScheme()
		Expect(k8sv1.AddToScheme(scheme)).To(Succeed())
		Expect(appsv1.AddToScheme(scheme)).To(Succeed())
		k8sClient, err = k8sclient.New(config, k8sclient.Options{Scheme: scheme})
		Expect(err).NotTo(HaveOccurred())

		nsSpec := &k8sv1.Namespace{ObjectMeta: metav1.ObjectMeta{GenerateName: testNamespace + "-"}}
		ns, err := clientset.CoreV1().Namespaces().Create(ctx, nsSpec, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())
		namespace = ns.Name
		klog.Infof("Using generated namespace: %s", namespace)

		DeferCleanup(func() {
			if debugMode {
				klog.Info("DEBUG_MODE is enabled, skipping final resource cleanup.")
				return
			}
			klog.Info("Tearing down test resources")
			clientset.CoreV1().Namespaces().Delete(ctx, namespace, metav1.DeleteOptions{})
			cancel()
		})

		klog.Info("Setting up comprehensive debug workloads and services")
		debugInfo, err = utils.SetupDebugWorkloads(ctx, clientset, k8sClient, namespace)
		Expect(err).NotTo(HaveOccurred())
	})

	It("Should have stable connectivity", func() {
		err := utils.RunTestPhase(afero.NewOsFs(), ctx, namespace, "Basic Connectivity", debugInfo, checkStrictEgressPolicy, bootstrapperIP)
		Expect(err).NotTo(HaveOccurred())
	})
})
