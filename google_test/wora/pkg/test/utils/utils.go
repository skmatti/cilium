package utils

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/ssh"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	networkv1 "k8s.io/cloud-provider-gcp/crd/apis/network/v1"
	"k8s.io/utils/pointer"
	k8sclient "sigs.k8s.io/controller-runtime/pkg/client"

	klog "gke-internal.googlesource.com/syllogi/sanitized-klog/third_party/klogv2"
	"gke-internal.googlesource.com/third_party/cilium/google_test/wora/e2e/pkg/test/wait"
)

const (
	woraTestImage          = "gcr.io/anthos-networking-ci/toolbox:wora-test"
	testContainerName      = "test"
	responderContainerName = "responder"
	curlContainerName      = "curl"
	ResponderPort          = 8080
	podDebugCommand        = `
		while true; do
			echo "=== IP Address ==="; ip address show;
			echo "=== IP Route ==="; ip route show;
			sleep 600s;
		done
		`
)

type CiliumConfig struct {
	Key   string
	Value string
}

type PodCustomization func(*corev1.Pod)

func WithAnnotation(key, value string) PodCustomization {
	return func(p *corev1.Pod) {
		if p.Annotations == nil {
			p.Annotations = make(map[string]string)
		}
		p.Annotations[key] = value
	}
}

func WithLabel(key, value string) PodCustomization {
	return func(p *corev1.Pod) {
		if p.Labels == nil {
			p.Labels = make(map[string]string)
		}
		p.Labels[key] = value
	}
}

func WithNodeSelector(nodeSelectorIP string) PodCustomization {
	return func(p *corev1.Pod) {
		if p.Spec.NodeSelector == nil {
			p.Spec.NodeSelector = make(map[string]string)
		}
		p.Spec.NodeSelector["baremetal.cluster.gke.io/k8s-ip"] = nodeSelectorIP
	}
}

func WithHostNetworking() PodCustomization {
	return func(p *corev1.Pod) {
		p.Spec.HostNetwork = true
	}
}

func WithResponderContainer() PodCustomization {
	return func(p *corev1.Pod) {
		responder := corev1.Container{
			Name:  responderContainerName,
			Image: "gcr.io/anthos-networking-ci/toolbox:wora-test",
			Command: []string{
				"/bin/sh", "-c", `POD_NAME=$(hostname)
					echo "Serving pod name: $POD_NAME on port 8080"
					while true; do
						{ echo -ne "HTTP/1.1 200 OK\r\nContent-Length: ${#POD_NAME}\r\n\r\n$POD_NAME"; } | nc -l -p 8080 -q 1;
					done`,
			},
			Ports: []corev1.ContainerPort{
				{
					ContainerPort: int32(ResponderPort),
					Name:          "http",
				},
			},
		}
		if len(p.Spec.Containers) == 0 {
			p.Spec.Containers = []corev1.Container{responder}
		} else {
			p.Spec.Containers = append(p.Spec.Containers, responder)
		}
	}
}

func WithAffinity(affinity *corev1.Affinity) PodCustomization {
	return func(p *corev1.Pod) {
		p.Spec.Affinity = affinity
	}
}

// NewCurlJob returns a Job object that runs a curl command against the given IP:port
// and checks if the response contains the expectedOutput. If yes, it exits successfully,
// otherwise it fails.
func NewCurlJob(jobName, ip, namespace string, port int, expectedOutput string) *batchv1.Job {
	script := fmt.Sprintf(`echo "Curling %s:%d and checking for '%s'..."
response=$(curl -s http://%s:%d)
echo "Response: $response"
if echo "$response" | grep -q "%s"; then
  echo "Test passed: Response contains '%s'"
  exit 0
else
  echo "Test failed: Response does not contain '%s'"
  exit 1
fi
`, ip, port, expectedOutput, ip, port, expectedOutput, expectedOutput, expectedOutput)

	return &batchv1.Job{
		TypeMeta: metav1.TypeMeta{
			APIVersion: batchv1.SchemeGroupVersion.String(),
			Kind:       "Job",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      jobName,
			Namespace: namespace,
		},
		Spec: batchv1.JobSpec{
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Name: jobName,
				},
				Spec: corev1.PodSpec{
					RestartPolicy: corev1.RestartPolicyNever,
					Containers: []corev1.Container{
						{
							Name:    curlContainerName,
							Image:   woraTestImage,
							Command: []string{"/bin/sh", "-c", script},
							Ports: []corev1.ContainerPort{
								{
									ContainerPort: int32(port),
									Protocol:      corev1.ProtocolTCP,
								},
							},
						},
					},
				},
			},
		},
	}
}

// JobComplete checks whether the job is marked as complete.
func JobComplete(j *batchv1.Job) error {
	if j == nil {
		return fmt.Errorf("empty job")
	}
	failed := jobCondition(j, batchv1.JobFailed)
	if failed != nil && failed.Status == corev1.ConditionTrue {
		return fmt.Errorf("job condition %q indicates failed: %#v: %w", batchv1.JobFailed, j.Status.Conditions, wait.ErrNotRetriable)
	}
	complete := jobCondition(j, batchv1.JobComplete)
	if complete == nil {
		return fmt.Errorf("job condition %q not found: %#v", batchv1.JobComplete, j.Status.Conditions)
	}
	if complete.Status != corev1.ConditionTrue {
		return fmt.Errorf("job condition %q not true: %#v", batchv1.JobComplete, complete)
	}
	return nil
}

func jobCondition(j *batchv1.Job, t batchv1.JobConditionType) *batchv1.JobCondition {
	for i, cond := range j.Status.Conditions {
		if cond.Type == t {
			return &j.Status.Conditions[i]
		}
	}
	return nil
}

type NetworkInfo struct {
	InterfaceName string
	NetworkName   string
	IPAddress     string
	IsDefault     bool
}

func CreatePod(ctx context.Context, cl k8sclient.Client, podName, namespace string, opts ...PodCustomization) (func(), error) {
	return CreatePodWithNetworkInterfaces(ctx, cl, podName, namespace, nil, nil, opts...)
}

// CreatePodWithNetworkInterfaces creates a Pod with specified network interfaces and their configurations
func CreatePodWithNetworkInterfaces(ctx context.Context, cl k8sclient.Client, podName, namespace string, networkInfos []NetworkInfo, additionCommands []string, opts ...PodCustomization) (func(), error) {
	var interfaceAnnotations []string
	cleanup := func() {
		cleanupResources(ctx, cl, podName, namespace, networkInfos)
	}
	command := strings.Join(additionCommands, "") + podDebugCommand
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      podName,
			Namespace: namespace,
		},
		Spec: corev1.PodSpec{
			Tolerations: []corev1.Toleration{
				{
					Operator: corev1.TolerationOpExists,
				},
			},
			Containers: []corev1.Container{
				{
					Name:            testContainerName,
					Image:           "gcr.io/anthos-networking-ci/toolbox:wora-test",
					Command:         []string{"/bin/sh", "-c", command},
					ImagePullPolicy: corev1.PullIfNotPresent,
					SecurityContext: &corev1.SecurityContext{
						Privileged: pointer.Bool(true),
					},
				},
			},
		},
	}

	defaultIntf := ""
	for _, info := range networkInfos {
		if info.IsDefault {
			if len(defaultIntf) != 0 {
				return cleanup, errors.New("found multiple default interfaces")
			}
			defaultIntf = info.InterfaceName
		}
		if err := createNetworkInterface(cl, podName, namespace, info); err != nil {
			return cleanup, err
		}
		interfaceAnnotations = append(interfaceAnnotations, fmt.Sprintf("{\"interfaceName\":\"%s\",\"interface\":\"%s-%s\"}", info.InterfaceName, podName, info.InterfaceName))
	}

	if len(interfaceAnnotations) != 0 {
		podAnnotations := map[string]string{
			networkv1.InterfaceAnnotationKey:        fmt.Sprintf("[%s]", strings.Join(interfaceAnnotations, ",")),
			networkv1.DefaultInterfaceAnnotationKey: defaultIntf,
		}
		pod.ObjectMeta.Annotations = podAnnotations
	}

	// Apply customization to the pod.
	for _, opt := range opts {
		opt(pod)
	}

	if err := cl.Create(ctx, pod); err != nil {
		return cleanup, fmt.Errorf("failed to create pod: %v", err)
	}

	if err := waitForPodReady(ctx, cl, podName, namespace); err != nil {
		return cleanup, err
	}

	klog.Infof("pod %s is created and ready", podName)
	return cleanup, nil
}

// createNetworkInterface creates a NetworkInterface resource
func createNetworkInterface(cl k8sclient.Client, podName, namespace string, networkInfo NetworkInfo) error {
	intf := networkv1.NetworkInterface{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-%s", podName, networkInfo.InterfaceName),
			Namespace: namespace,
		},
		Spec: networkv1.NetworkInterfaceSpec{
			NetworkName: networkInfo.NetworkName,
		},
	}
	if len(networkInfo.IPAddress) != 0 {
		intf.Spec.IpAddresses = []string{networkInfo.IPAddress}
	}
	if err := cl.Create(context.TODO(), &intf); err != nil {
		return fmt.Errorf("failed to create network interface: %v", err)
	}
	return nil
}

// CreateTestNamespace creates a Kubernetes namespace if it does not already exist
func CreateTestNamespace(ctx context.Context, cl k8sclient.Client, namespace string) error {
	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: namespace,
		},
	}
	if err := cl.Create(ctx, ns); err != nil {
		if apierrors.IsAlreadyExists(err) {
			return nil
		}
		return fmt.Errorf("failed to create namespace: %v", err)
	}
	return nil
}

// cleanupResources deletes the pod and all associated network interfaces
func cleanupResources(ctx context.Context, cl k8sclient.Client, podName, namespace string, networkInfos []NetworkInfo) {
	// Delete the pod
	err := cl.Delete(ctx, &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      podName,
			Namespace: namespace,
		},
	})
	if err != nil {
		klog.Warningf("Failed to delete Pod %s: %v", podName, err)
	} else {
		klog.Infof("Deleting Pod %s", podName)
	}

	// Delete associated network interfaces
	for _, info := range networkInfos {
		niName := fmt.Sprintf("%s-%s", podName, info.InterfaceName)
		err := cl.Delete(ctx, &networkv1.NetworkInterface{
			ObjectMeta: metav1.ObjectMeta{
				Name:      niName,
				Namespace: namespace,
			},
		})
		if err != nil {
			klog.Warningf("Failed to delete NetworkInterface %s: %v", niName, err)
		} else {
			klog.Infof("Deleting NetworkInterface %s", niName)
		}
	}
}

// RunCurlFromPod executes a curl command from a specific pod to test connectivity
func RunCurlFromPod(ctx context.Context, cl k8sclient.Client, sourcePodName, targetPodName, targetIP string, port int, namespace string) error {
	cmd := exec.Command("kubectl", "exec", sourcePodName, "-n", namespace, "--", "curl", fmt.Sprintf("http://%s:%d", targetIP, port))
	return runCurlCommand(cmd, sourcePodName, targetPodName, targetIP, port)
}

func RunCurlFromPodWithTimeoutLimit(ctx context.Context, cl k8sclient.Client, sourcePodName, targetPodName, targetIP string, port int, namespace string, timeout int) error {
	cmd := exec.Command(
		"kubectl", "exec", sourcePodName, "-n", namespace, "--",
		"curl", "--max-time", fmt.Sprintf("%d", timeout), fmt.Sprintf("http://%s:%d", targetIP, port),
	)
	return runCurlCommand(cmd, sourcePodName, targetPodName, targetIP, port)
}

func runCurlCommand(cmd *exec.Cmd, sourcePodName, targetPodName, targetIP string, port int) error {
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to execute curl command: %v, output: %s", err, string(output))
	}

	if !strings.Contains(string(output), "200 OK") && !strings.Contains(string(output), targetPodName) {
		return fmt.Errorf("unexpected curl response: %s", string(output))
	}

	klog.Infof("Curl command successful from pod %s to %s:%d", sourcePodName, targetIP, port)
	return nil
}

// VerifyCurlFromPod retry curl command with 1 min timeout and expected 2 consecutive expected connection
func VerifyCurlFromPod(ctx context.Context, cl k8sclient.Client, sourcePodName, targetPodName, targetIP string, port int, namespace string, expectSuccess bool) error {
	minConsecutiveSuccess := 2
	return wait.WaitForSuccessContext(ctx, fmt.Sprintf("Expected %d consecutive curl %t", minConsecutiveSuccess, expectSuccess), wait.WaitingMedium, func(ctx context.Context) error {
		for i := 1; i < minConsecutiveSuccess+1; i++ {
			err := RunCurlFromPodWithTimeoutLimit(ctx, cl, sourcePodName, targetPodName, targetIP, port, namespace, 1)
			if expectSuccess && err != nil {
				return fmt.Errorf("expect curl success, %d time fail: %v", i, err)
			} else if !expectSuccess && err == nil {
				return fmt.Errorf("expect curl fail, %d time success", i)
			}
		}
		return nil
	})
}

func waitForPodReady(ctx context.Context, c k8sclient.Client, podName, podNamespace string) error {
	pod := corev1.Pod{}
	podReady := func(ctx context.Context) error {
		if err := c.Get(ctx, k8sclient.ObjectKey{Name: podName, Namespace: podNamespace}, &pod); err != nil {
			return err
		}
		if !isPodReady(&pod.Status) {
			return fmt.Errorf("pod %s is not ready yet", podName)
		}
		return nil
	}
	if err := wait.WaitForSuccessContext(ctx, "Check Server Pod Readiness", wait.WaitingLong, podReady); err != nil {
		return fmt.Errorf("unable to ensure pod readiness: %v", err)
	}
	return nil
}

func isPodReady(status *corev1.PodStatus) bool {
	if status == nil {
		return false
	}
	for _, condition := range status.Conditions {
		if condition.Type == corev1.PodReady {
			return condition.Status == corev1.ConditionTrue
		}
	}
	return false
}

func FetchPodLogs(ctx context.Context, c kubernetes.Interface, podName, namespace string) (string, error) {
	podLogOptions := &corev1.PodLogOptions{Container: testContainerName}

	// Request the logs for the given pod and container
	req := c.CoreV1().Pods(namespace).GetLogs(podName, podLogOptions)

	// Open a stream to fetch the logs
	podLogs, err := req.Stream(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to open log stream for pod %s: %v", podName, err)
	}
	defer podLogs.Close()

	// Read logs from the stream
	logs, err := ioutil.ReadAll(podLogs)
	if err != nil {
		return "", fmt.Errorf("failed to read logs for pod %s: %v", podName, err)
	}

	return string(logs), nil
}

// DeleteIfExists deletes a Kubernetes object, ignoring "not found" errors.
func DeleteIfExists(ctx context.Context, cl k8sclient.Client, obj k8sclient.Object, objType string) error {
	err := cl.Delete(ctx, obj)
	name := fmt.Sprintf("%s object %s", objType, obj.GetName())
	if err != nil {
		if apierrors.IsNotFound(err) {
			klog.Infof("%s already deleted", name)
			return nil
		} else {
			return fmt.Errorf("failed to delete %s: %v", name, err)
		}
	}

	klog.Infof("%s deleted successfully", name)
	return nil
}

// DeleteAndWait deletes a Kubernetes object and waits for it to be removed.
func DeleteAndWait(ctx context.Context, cl k8sclient.Client, obj k8sclient.Object, objType string) error {
	err := DeleteIfExists(ctx, cl, obj, objType)
	if err != nil {
		return err
	}

	name := fmt.Sprintf("%s object %s", objType, obj.GetName())
	return wait.WaitForSuccessContext(ctx, fmt.Sprintf("delete %s", name), wait.WaitingMedium, func(ctx context.Context) error {
		err := cl.Get(ctx, k8sclient.ObjectKeyFromObject(obj), obj)
		if err != nil {
			if apierrors.IsNotFound(err) {
				// Object deleted successfully
				return nil
			}
			return fmt.Errorf("failed to get %s: %v", name, err)
		}
		// Retry until not found
		return fmt.Errorf("%s still exists", name)
	})
}

func FetchPodIP(ctx context.Context, cl k8sclient.Client, podName, ns string) (string, error) {
	pod := corev1.Pod{}
	err := cl.Get(ctx, k8sclient.ObjectKey{Namespace: ns, Name: podName}, &pod)
	if err != nil {
		return "", fmt.Errorf("failed to get pod %s: %v", podName, err)
	}

	if len(pod.Status.PodIP) == 0 {
		return "", fmt.Errorf("IP not found for pod %s", podName)
	}
	return pod.Status.PodIP, nil
}

// ValidateCiliumConfigFlag fetches the "cilium-config" ConfigMap in kube-system,
// checks whether configurations are set as expected.
func ValidateCiliumConfigFlag(ctx context.Context, cl k8sclient.Client, cfg []CiliumConfig) (bool, error) {
	configMap := &corev1.ConfigMap{}
	err := cl.Get(ctx, k8sclient.ObjectKey{
		Namespace: "kube-system",
		Name:      "cilium-config",
	}, configMap)
	if err != nil {
		return false, fmt.Errorf("failed to get cilium-config ConfigMap: %w", err)
	}

	for _, want := range cfg {
		actualVal, found := configMap.Data[want.Key]
		if !found || actualVal != want.Value {
			return false, nil
		}
	}
	return true, nil
}

func DeletePod(ctx context.Context, cl k8sclient.Client, podName, namespace string) {
	cleanupResources(ctx, cl, podName, namespace, nil)
}

func WaitForPodDeletion(ctx context.Context, cl k8sclient.Client, podName, namespace string) error {
	return wait.WaitForSuccessContext(ctx, "Wait for pod deletion", wait.WaitingMedium, func(ctx context.Context) error {
		pod := &corev1.Pod{}
		err := cl.Get(ctx, k8sclient.ObjectKey{Name: podName, Namespace: namespace}, pod)
		if err != nil {
			if apierrors.IsNotFound(err) {
				klog.Infof("Pod %s in namespace %s deleted successfully", podName, namespace)
				return nil
			}
			klog.Errorf("Error getting pod %s in namespace %s: %v", podName, namespace, err)
			return err
		}
		klog.Infof("Pod %s in namespace %s still exists", podName, namespace)
		return fmt.Errorf("pod %s is still present", podName)
	})
}

func GetRequiredNumberOfNodeIPsByLabel(cl k8sclient.Client, labelKey string, requiredNumberOfNodeIPs int) ([]string, error) {
	if requiredNumberOfNodeIPs <= 0 {
		return nil, fmt.Errorf("Required number of nodeIPs is %v", requiredNumberOfNodeIPs)
	}

	nodeList := &corev1.NodeList{}
	selector, err := metav1.ParseToLabelSelector(labelKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse label selector: %w", err)
	}
	labelSelector, err := metav1.LabelSelectorAsSelector(selector)
	if err != nil {
		return nil, fmt.Errorf("failed to convert label selector: %w", err)
	}

	err = cl.List(context.TODO(), nodeList, &k8sclient.ListOptions{LabelSelector: labelSelector})
	if err != nil {
		return nil, err
	}

	var nodeIPs []string
	currentNodeIPcount := 0
	for _, node := range nodeList.Items {
		if currentNodeIPcount >= requiredNumberOfNodeIPs {
			break
		}
		for _, address := range node.Status.Addresses {
			if address.Type == corev1.NodeInternalIP {
				nodeIPs = append(nodeIPs, address.Address)
				currentNodeIPcount++
				break
			}
		}
	}
	if len(nodeIPs) < requiredNumberOfNodeIPs {
		return nil, fmt.Errorf("Required number of nodes: %v less than available number of nodes: %v with lable: %s", requiredNumberOfNodeIPs, len(nodeIPs), labelKey)
	}
	return nodeIPs, nil
}

func WaitForServiceReadiness(ctx context.Context, c k8sclient.Client, serviceName string, serviceNamespace string, serviceType corev1.ServiceType) error {
	service := corev1.Service{}
	serviceReady := func(ctx context.Context) error {
		if err := c.Get(ctx, k8sclient.ObjectKey{Name: serviceName, Namespace: serviceNamespace}, &service); err != nil {
			return err
		}
		if service.Spec.Type != serviceType {
			return fmt.Errorf("service %s is not updated yet", serviceName)
		}
		if serviceType == corev1.ServiceTypeLoadBalancer {
			ingresses := service.Status.LoadBalancer.Ingress
			if len(ingresses) == 0 || len(ingresses[0].IP) == 0 {
				return fmt.Errorf("no ingress assigned to the service %s", serviceName)
			}
		}
		return nil
	}
	if err := wait.WaitForSuccessContext(ctx, "Check Service Readiness", wait.WaitingMedium, serviceReady); err != nil {
		return fmt.Errorf("unable to ensure service readiness: %v", err)
	}
	return nil
}

func NodePortReadiness(ctx context.Context, c k8sclient.Client, serviceName string, serviceNamespace string, serviceType corev1.ServiceType) (error, int32) {
	service := corev1.Service{}
	var nodeport int32
	serviceReady := func(ctx context.Context) error {
		if err := c.Get(ctx, k8sclient.ObjectKey{Name: serviceName, Namespace: serviceNamespace}, &service); err != nil {
			return err
		}
		if service.Spec.Type != serviceType {
			return fmt.Errorf("service %s is not updated yet", serviceName)
		}
		if service.Spec.Ports[0].NodePort == 0 {
			return fmt.Errorf("no nodeport is assigned to the service: %s", serviceName)
		}
		nodeport = service.Spec.Ports[0].NodePort
		return nil
	}
	if err := wait.WaitForSuccessContext(ctx, "Check Service Readiness", wait.WaitingMedium, serviceReady); err != nil {
		return fmt.Errorf("unable to ensure service readiness: %v", err), 0
	}
	return nil, nodeport
}

func executeSSHCommandToBootstapper(privateKeyPath, bootstrapperIP, targetIP string, port int) (string, error) {
	// Read the private key.
	privateKey, err := ioutil.ReadFile(privateKeyPath)
	if err != nil {
		return "", fmt.Errorf("failed to read private key: %v", err)
	}

	// Create the signer from the private key.
	signer, err := ssh.ParsePrivateKey(privateKey)
	if err != nil {
		return "", fmt.Errorf("failed to parse private key: %v", err)
	}

	// Configure SSH client.
	config := &ssh.ClientConfig{
		User: "root",
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // Insecure, but matches "-o StrictHostKeyChecking=no"
	}

	// Connect to the SSH server.
	client, err := ssh.Dial("tcp", net.JoinHostPort(bootstrapperIP, "22"), config)
	if err != nil {
		return "", fmt.Errorf("failed to connect to SSH server: %v", err)
	}
	defer client.Close()

	// Create a new SSH session.
	session, err := client.NewSession()
	if err != nil {
		return "", fmt.Errorf("failed to create SSH session: %v", err)
	}
	defer session.Close()

	// Construct the command.
	command := fmt.Sprintf("curl http://%s:%d", targetIP, port)

	// Capture the output.
	var stdoutBuf bytes.Buffer
	session.Stdout = &stdoutBuf
	var stderrBuf bytes.Buffer
	session.Stderr = &stderrBuf

	// Execute the command.
	err = session.Run(command)
	if err != nil {
		return "", fmt.Errorf("failed to execute command: %v, stderr: %s", err, stderrBuf.String())
	}

	return stdoutBuf.String(), nil
}

func RunCurlFromBootstrapper(ctx context.Context, cl k8sclient.Client, targetIP string, port int32) error {
	kubeconfig := os.Getenv("KUBECONFIG")
	directory := filepath.Dir(kubeconfig)
	bootstrapperIP, err := extractBootstrapperIPFromFile(directory)
	privateKeyPath := fmt.Sprintf("%s/id_rsa", directory)
	if err != nil {
		return err
	}

	curlExecuted := func(ctx context.Context) error {

		output, err := executeSSHCommandToBootstapper(privateKeyPath, bootstrapperIP, targetIP, int(port))
		if err != nil {
			return fmt.Errorf("failed to execute curl command: %v, output: %s", err, output)
		}

		if !strings.Contains(output, "200 OK") {
			return fmt.Errorf("unexpected curl response: %s", output)
		}

		klog.Infof("Curl command successful from bootstapper to %s:%d", targetIP, port)
		return nil
	}
	if err := wait.WaitForSuccessContext(ctx, "Waiting for curl success", wait.WaitingMedium, curlExecuted); err != nil {
		return fmt.Errorf("unable to connect: %v", err)
	}
	return nil
}

func extractBootstrapperIPFromFile(directory string) (string, error) {
	filename := fmt.Sprintf("%s/metadata.json", directory)
	metadata, err := os.ReadFile(filename)
	if err != nil {
		return "", err
	}
	var data map[string]interface{}
	err = json.Unmarshal(metadata, &data)
	if err != nil {
		return "", fmt.Errorf("error unmarshaling JSON: %w", err)
	}
	bootstrapperIP, ok := data["EnvVar.Output.BootStrapExternalIP"].(string)
	if !ok {
		return "", fmt.Errorf("IP address not found in file")
	}
	return bootstrapperIP, nil
}

func KubectlApply(manifest string) error {
	return kubectlAction("apply", manifest)
}

func KubectlDelete(manifest string) error {
	return kubectlAction("delete", manifest)
}

func kubectlAction(action, manifest string) error {
	cmd := exec.Command("kubectl", action, "-f", "-")
	cmd.Stdin = strings.NewReader(manifest)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to execute curl command: %v, output: %s", err, string(output))
	}
	return nil
}
