package k8s

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/cilium/cilium/pkg/controller"
	k8sConst "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	clientset "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned"
	k8sconfig "github.com/cilium/cilium/pkg/k8s/config"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	watcher_client "github.com/cilium/cilium/pkg/k8s/slim/k8s/clientset"
	k8sversion "github.com/cilium/cilium/pkg/k8s/version"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/version"
	"github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/connrotation"
)

// logging field definitions
const (
	// subsysK8s is the value for logfields.LogSubsys
	subsysK8s = "k8s"
)

var (
	// log is the k8s package logger object.
	log = logging.DefaultLogger.WithField(logfields.LogSubsys, subsysK8s)
)

// Init initializes the Kubernetes package. It is required to call Configure()
// beforehand.
func Init(conf k8sconfig.Configuration) error {
	k8sRestClient, closeAllDefaultClientConns, err := createDefaultClient()
	if err != nil {
		return fmt.Errorf("unable to create k8s client: %s", err)
	}

	closeAllCiliumClientConns, err := createDefaultCiliumClient()
	if err != nil {
		return fmt.Errorf("unable to create cilium k8s client: %s", err)
	}

	heartBeat := func(ctx context.Context) error {
		// Kubernetes does a get node of the node that kubelet is running [0]. This seems excessive in
		// our case because the amount of data transferred is bigger than doing a Get of /healthz.
		// For this reason we have picked to perform a get on `/healthz` instead a get of a node.
		//
		// [0] https://github.com/kubernetes/kubernetes/blob/v1.17.3/pkg/kubelet/kubelet_node_status.go#L423
		res := k8sRestClient.Get().Resource("healthz").Do(ctx)
		return res.Error()
	}

	if option.Config.K8sHeartbeatTimeout != 0 {
		controller.NewManager().UpdateController("k8s-heartbeat",
			controller.ControllerParams{
				DoFunc: func(context.Context) error {
					runHeartbeat(
						heartBeat,
						option.Config.K8sHeartbeatTimeout,
						closeAllDefaultClientConns,
						closeAllCiliumClientConns,
					)
					return nil
				},
				RunInterval: option.Config.K8sHeartbeatTimeout,
			},
		)
	}

	if err := k8sversion.Update(Client(), conf); err != nil {
		return err
	}

	if !k8sversion.Capabilities().MinimalVersionMet {
		return fmt.Errorf("k8s version (%v) is not meeting the minimal requirement (%v)",
			k8sversion.Version(), k8sversion.MinimalVersionConstraint)
	}

	return nil
}

// createClient creates a new client to access the Kubernetes API
func createClient(config *rest.Config, cs kubernetes.Interface) error {
	stop := make(chan struct{})
	timeout := time.NewTimer(time.Minute)
	defer timeout.Stop()
	var err error
	wait.Until(func() {
		// FIXME: Use config.String() when we rebase to latest go-client
		log.WithField("host", config.Host).Info("Establishing connection to apiserver")
		err = isConnReady(cs)
		if err == nil {
			close(stop)
			return
		}
		select {
		case <-timeout.C:
			log.WithError(err).WithField(logfields.IPAddr, config.Host).Error("Unable to contact k8s api-server")
			close(stop)
		default:
		}
	}, 5*time.Second, stop)
	if err == nil {
		log.Info("Connected to apiserver")
	}
	return err
}

// isConnReady returns the err for the kube-system namespace get
func isConnReady(c kubernetes.Interface) error {
	_, err := c.CoreV1().Namespaces().Get(context.TODO(), "kube-system", metav1.GetOptions{})
	return err
}

func createDefaultClient() (rest.Interface, func(), error) {
	restConfig, err := CreateConfig()
	if err != nil {
		return nil, nil, fmt.Errorf("unable to create k8s client rest configuration: %s", err)
	}
	restConfig.ContentConfig.ContentType = `application/vnd.kubernetes.protobuf`

	closeAllConns := setDialer(restConfig)

	createdK8sClient, err := kubernetes.NewForConfig(restConfig)
	if err != nil {
		return nil, nil, err
	}
	err = createClient(restConfig, createdK8sClient)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to create k8s client: %s", err)
	}

	k8sCLI.Interface = createdK8sClient

	createK8sWatcherCli, err := watcher_client.NewForConfig(restConfig)
	if err != nil {
		return nil, nil, err
	}

	k8sWatcherCLI.Interface = createK8sWatcherCli

	return createdK8sClient.RESTClient(), closeAllConns, nil
}

func createDefaultCiliumClient() (func(), error) {
	restConfig, err := CreateConfig()
	if err != nil {
		return nil, fmt.Errorf("unable to create k8s client rest configuration: %s", err)
	}

	closeAllConns := setDialer(restConfig)
	createdCiliumK8sClient, err := clientset.NewForConfig(restConfig)
	if err != nil {
		return nil, fmt.Errorf("unable to create k8s client: %s", err)
	}

	k8sCiliumCLI.Interface = createdCiliumK8sClient

	return closeAllConns, nil
}

func runHeartbeat(heartBeat func(context.Context) error, timeout time.Duration, closeAllConns ...func()) {
	done := make(chan error)
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	go func() {
		// If we have reached up to this point to perform a heartbeat to
		// kube-apiserver then we should close the connections if we receive
		// any error at all except if we receive a http.StatusTooManyRequests
		// which means the server is overloaded and only for this reason we
		// will not close all connections.
		err := heartBeat(ctx)
		switch t := err.(type) {
		case *errors.StatusError:
			if t.ErrStatus.Code != http.StatusTooManyRequests {
				done <- err
			}
		default:
			done <- err
		}
		close(done)
	}()

	select {
	case err := <-done:
		if err != nil {
			log.WithError(err).Warn("Network status error received, restarting client connections")
			for _, fn := range closeAllConns {
				fn()
			}
		}
	case <-ctx.Done():
		log.Warn("Heartbeat timed out, restarting client connections")
		for _, fn := range closeAllConns {
			fn()
		}
	}
}

var (
	// k8sCLI is the default client.
	k8sCLI = &K8sClient{}

	// k8sWatcherCLI is the client dedicated k8s structure watchers.
	k8sWatcherCLI = &K8sClient{}

	// k8sCiliumCLI is the default Cilium client.
	k8sCiliumCLI = &K8sCiliumClient{}
)

// K8sClient is a wrapper around kubernetes.Interface.
type K8sClient struct {
	// kubernetes.Interface is the object through which interactions with
	// Kubernetes are performed.
	kubernetes.Interface
}

// K8sCiliumClient is a wrapper around clientset.Interface.
type K8sCiliumClient struct {
	clientset.Interface
}

// Client returns the default Kubernetes client.
func Client() *K8sClient {
	return k8sCLI
}

// WatcherClient returns the client dedicated to K8s watchers.
func WatcherClient() *K8sClient {
	return k8sWatcherCLI
}

// CiliumClient returns the default Cilium Kubernetes client.
func CiliumClient() *K8sCiliumClient {
	return k8sCiliumCLI
}

// CreateConfig creates a client configuration based on the configured API
// server and Kubeconfig path
func CreateConfig() (*rest.Config, error) {
	return createConfig(GetAPIServerURL(), GetKubeconfigPath(), GetQPS(), GetBurst())
}

// createConfig creates a rest.Config for connecting to k8s api-server.
//
// The precedence of the configuration selection is the following:
// 1. kubeCfgPath
// 2. apiServerURL (https if specified)
// 3. rest.InClusterConfig().
func createConfig(apiServerURL, kubeCfgPath string, qps float32, burst int) (*rest.Config, error) {
	var (
		config *rest.Config
		err    error
	)
	userAgent := fmt.Sprintf("Cilium %s", version.Version)

	switch {
	// If the apiServerURL and the kubeCfgPath are empty then we can try getting
	// the rest.Config from the InClusterConfig
	case apiServerURL == "" && kubeCfgPath == "":
		if config, err = rest.InClusterConfig(); err != nil {
			return nil, err
		}
	case kubeCfgPath != "":
		if config, err = clientcmd.BuildConfigFromFlags("", kubeCfgPath); err != nil {
			return nil, err
		}
	case strings.HasPrefix(apiServerURL, "https://"):
		if config, err = rest.InClusterConfig(); err != nil {
			return nil, err
		}
		config.Host = apiServerURL
	default:
		config = &rest.Config{Host: apiServerURL, UserAgent: userAgent}
	}

	setConfig(config, userAgent, qps, burst)
	return config, nil
}

func setConfig(config *rest.Config, userAgent string, qps float32, burst int) {
	if config.UserAgent != "" {
		config.UserAgent = userAgent
	}
	if qps != 0.0 {
		config.QPS = qps
	}
	if burst != 0 {
		config.Burst = burst
	}
}

func setDialer(config *rest.Config) func() {
	if option.Config.K8sHeartbeatTimeout == 0 {
		return func() {}
	}
	ctx := (&net.Dialer{
		Timeout:   option.Config.K8sHeartbeatTimeout,
		KeepAlive: option.Config.K8sHeartbeatTimeout,
	}).DialContext
	dialer := connrotation.NewDialer(ctx)
	config.Dial = dialer.DialContext
	return dialer.CloseAll
}

// GetPodMetadata returns the labels and annotations of the pod with the given
// namespace / name.
func GetPodMetadata(pod *slim_corev1.Pod) (containerPorts []slim_corev1.ContainerPort, lbls map[string]string, retAnno map[string]string, retErr error) {
	namespace := pod.Namespace
	scopedLog := log.WithFields(logrus.Fields{
		logfields.K8sNamespace: namespace,
		logfields.K8sPodName:   pod.Name,
	})
	scopedLog.Debug("Connecting to k8s local stores to retrieve labels for pod")

	objMetaCpy := pod.ObjectMeta.DeepCopy()
	annotations := objMetaCpy.Annotations
	k8sLabels := objMetaCpy.Labels
	if k8sLabels == nil {
		k8sLabels = map[string]string{}
	}
	k8sLabels[k8sConst.PodNamespaceLabel] = namespace

	if pod.Spec.ServiceAccountName != "" {
		k8sLabels[k8sConst.PolicyLabelServiceAccount] = pod.Spec.ServiceAccountName
	} else {
		delete(k8sLabels, k8sConst.PolicyLabelServiceAccount)
	}

	for _, containers := range pod.Spec.Containers {
		for _, cp := range containers.Ports {
			containerPorts = append(containerPorts, cp)
		}
	}

	return containerPorts, k8sLabels, annotations, nil
}
