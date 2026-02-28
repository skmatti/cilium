package utils

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	gcpnetworkv1 "github.com/GoogleCloudPlatform/gke-networking-api/apis/network/v1"
	networkclientset "github.com/GoogleCloudPlatform/gke-networking-api/client/network/clientset/versioned"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes"
	networkv1 "k8s.io/cloud-provider-gcp/crd/apis/network/v1"
	"k8s.io/utils/ptr"
	k8sclient "sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/spf13/afero"
	networkutils "gke-internal.googlesource.com/anthos-networking/test-infra/pkg/network"
	klog "gke-internal.googlesource.com/syllogi/sanitized-klog/third_party/klogv2"
	"gke-internal.googlesource.com/third_party/cilium/google_test/wora/e2e/pkg/test/wait"
	appsv1 "k8s.io/api/apps/v1"
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

var ResponderContainer = corev1.Container{
	Name:  responderContainerName,
	Image: woraTestImage,
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

type PodCustomization func(*corev1.Pod)

func WithHostNetworking() PodCustomization {
	return func(p *corev1.Pod) {
		p.Spec.HostNetwork = true
	}
}

func WithAnnotation(key, value string) PodCustomization {
	return func(p *corev1.Pod) {
		if p.Annotations == nil {
			p.Annotations = make(map[string]string)
		}
		p.Annotations[key] = value
	}
}

func WithNodeName(nodeName string) PodCustomization {
	return func(p *corev1.Pod) {
		p.Spec.NodeName = nodeName
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

func WithContainers(containers []corev1.Container) PodCustomization {
	return func(p *corev1.Pod) {
		p.Spec.Containers = containers
	}
}

func WithResponderContainer() PodCustomization {
	return func(p *corev1.Pod) {
		if len(p.Spec.Containers) == 0 {
			p.Spec.Containers = []corev1.Container{ResponderContainer}
		} else {
			p.Spec.Containers = append(p.Spec.Containers, ResponderContainer)
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
	IPAMMode      networkv1.IPAMModeType
}

// CreateService create a service from corev1 object
func CreateService(ctx context.Context, cl k8sclient.Client, service *corev1.Service) error {
	if err := cl.Create(ctx, service); err != nil {
		if apierrors.IsAlreadyExists(err) {
			klog.Infof("Service already exists.")
			return nil
		}
		return fmt.Errorf("failed to create service: %v", err)
	}
	klog.Infof("service %s created successfully", service.Name)
	return nil
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
					Image:           woraTestImage,
					Command:         []string{"/bin/sh", "-c", command},
					ImagePullPolicy: corev1.PullIfNotPresent,
					SecurityContext: &corev1.SecurityContext{
						Privileged: ptr.To(true),
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
		if info.IPAMMode == networkv1.InternalMode {
			interfaceAnnotations = append(interfaceAnnotations, fmt.Sprintf("{\"interfaceName\":\"%s\",\"network\":\"%s\"}", info.InterfaceName, info.NetworkName))
		} else {
			if err := createNetworkInterface(cl, podName, namespace, info); err != nil {
				return cleanup, err
			}
			interfaceAnnotations = append(interfaceAnnotations, fmt.Sprintf("{\"interfaceName\":\"%s\",\"interface\":\"%s-%s\"}", info.InterfaceName, podName, info.InterfaceName))
		}
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
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      podName,
			Namespace: namespace,
		},
	}
	if err := DeleteIfExists(ctx, cl, pod); err != nil {
		klog.Warningf("Failed to delete Pod %s: %v", podName, err)
	}

	// Delete associated network interfaces
	for _, info := range networkInfos {
		if info.IPAMMode == networkv1.InternalMode {
			continue
		}
		niName := fmt.Sprintf("%s-%s", podName, info.InterfaceName)
		ni := &networkv1.NetworkInterface{
			ObjectMeta: metav1.ObjectMeta{
				Name:      niName,
				Namespace: namespace,
			},
		}
		if err := DeleteIfExists(ctx, cl, ni); err != nil {
			klog.Warningf("Failed to delete NetworkInterface %s: %v", niName, err)
		}
	}
}

// CurlOptions specifies options for running a curl command from a pod.
type CurlOptions struct {
	SourcePodName   string
	SourceNamespace string
	TargetIP        string
	TargetPort      int
	TimeoutSeconds  int
	// WantFailure, if true, indicates that the curl command is expected to fail.
	// The default expected failure is a timeout (exit status 28).
	WantFailure bool
	// WantOutput, if not empty, specifies a list of substring to look for in the curl response or error.
	// The function passes if the actual output contains at least one substring from this list.
	// If WantFailure is false, it overrides the default
	// success string ("200 OK"). If WantFailure is true, it overrides the
	// default failure string ("exit status 28").
	WantOutput []string
}

// RunCurlFromPod executes a curl command from a pod with the specified options.
func RunCurlFromPod(opts CurlOptions) (string, error) {
	const (
		curlSuccessMsg = "200 OK"
		curlTimeoutMsg = "exit status 28"
	)

	curlArgs := []string{"-sf"} // -s for silent, -f to fail on server errors
	if opts.TimeoutSeconds > 0 {
		curlArgs = append(curlArgs, "--max-time", fmt.Sprintf("%d", opts.TimeoutSeconds))
	}
	curlArgs = append(curlArgs, fmt.Sprintf("http://%s:%d", opts.TargetIP, opts.TargetPort))

	cmdArgs := []string{"exec", opts.SourcePodName, "-n", opts.SourceNamespace, "--", "curl"}
	cmdArgs = append(cmdArgs, curlArgs...)
	cmd := exec.Command("kubectl", cmdArgs...)

	outputBytes, err := cmd.CombinedOutput()
	output := string(outputBytes)

	if opts.WantFailure {
		if err == nil {
			return output, fmt.Errorf("expected curl to fail, but it succeeded, output: %s", output)
		}

		expectedFailureMsgs := []string{curlTimeoutMsg}
		if len(opts.WantOutput) > 0 {
			expectedFailureMsgs = opts.WantOutput
		}

		found := false
		for _, msg := range expectedFailureMsgs {
			if strings.Contains(err.Error(), msg) {
				found = true
				break
			}
		}

		if !found {
			return output, fmt.Errorf("expected curl to fail with one of the expected substrings %q, but got different error: %v, output: %s", expectedFailureMsgs, err, output)
		}
		return output, nil // Expected failure occurred.
	}

	// We expect success.
	if err != nil {
		return output, fmt.Errorf("expected curl to succeed, but got error: %v, output: %s", err, output)
	}
	klog.Infof("curl to %s succeed", fmt.Sprintf("http://%s:%d", opts.TargetIP, opts.TargetPort))

	if len(opts.WantOutput) > 0 {
		found := false
		for _, msg := range opts.WantOutput {
			if strings.Contains(output, msg) {
				found = true
				break
			}
		}
		if !found {
			return output, fmt.Errorf("curl response did not contain any of the expected substrings %q, output: %s", opts.WantOutput, output)
		}
	}
	return output, nil
}

// VerifyCurlFromPod retries a curl command with a 1-minute timeout and expects
// a number of consecutive successful or failed connections.
func VerifyCurlFromPodWithMultipleOutputs(ctx context.Context, namespace, sourcePodName, targetIP string, port int, wantSuccess bool, wantOutput []string) error {
	const minConsecutiveChecks = 2
	cmdStr := fmt.Sprintf("from %s/%s to %s:%d", namespace, sourcePodName, targetIP, port)
	waitMsg := fmt.Sprintf("Expected %d consecutive successful curls %s", minConsecutiveChecks, cmdStr)
	if !wantSuccess {
		waitMsg = fmt.Sprintf("Expected %d consecutive failed curls %s", minConsecutiveChecks, cmdStr)
	}
	opts := CurlOptions{
		SourcePodName:   sourcePodName,
		SourceNamespace: namespace,
		TargetIP:        targetIP,
		TargetPort:      port,
		TimeoutSeconds:  1,
		WantFailure:     !wantSuccess,
		WantOutput:      wantOutput,
	}

	return wait.WaitForSuccessContext(ctx, waitMsg, wait.WaitingMedium, func(ctx context.Context) error {
		for i := 0; i < minConsecutiveChecks; i++ {
			if _, err := RunCurlFromPod(opts); err != nil {
				return fmt.Errorf("curl check failed on attempt %d: %w", i+1, err)
			}
		}
		return nil
	})
}

func VerifyCurlFromPod(ctx context.Context, namespace, sourcePodName, targetIP string, port int, wantSuccess bool, wantOutput string) error {
	// Recreate the logic to call RunCurlFromPod, translating the single string to a list.
	var outputs []string
	if wantOutput != "" {
		outputs = []string{wantOutput}
	}
	return VerifyCurlFromPodWithMultipleOutputs(ctx, namespace, sourcePodName, targetIP, port, wantSuccess, outputs)
}

func NodeInterfaceIPFromPod(ctx context.Context, sourcePodName, nodeInterfaceName string, namespace string) (string, error) {
	cmd := exec.Command(
		"kubectl", "exec", sourcePodName, "-n", namespace, "--",
		"/bin/sh", "-c", fmt.Sprintf("ip -4 -o addr show dev %s | awk '{print $4}'", nodeInterfaceName),
	)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("failed to execute curl command: %v, output: %s", err, string(output))
	}
	klog.Infof("NodeInterfaceIPFromPod: %s", string(output))
	return string(output), nil
}

func RunPingFromPodWithTimeoutLimit(ctx context.Context, sourcePodName, namespace string, targetIP string, timeout int) error {
	cmd := exec.Command(
		"kubectl", "exec", sourcePodName, "-n", namespace, "--",
		"ping", "-c", "3", "-W", fmt.Sprintf("%d", timeout), fmt.Sprintf("%s", targetIP),
	)
	return runPingCommand(cmd, sourcePodName, targetIP)
}

func runPingCommand(cmd *exec.Cmd, sourcePodName, targetIP string) error {
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to execute ping command: %v, output: %s", err, string(output))
	}
	expectedPayload := fmt.Sprintf("bytes from %v", targetIP)
	if !strings.Contains(string(output), expectedPayload) {
		return fmt.Errorf("unexpected ping response: %s", string(output))
	}

	klog.Infof("Ping command successful from pod %s to %s", sourcePodName, targetIP)
	return nil
}

func waitForPodReady(ctx context.Context, c k8sclient.Client, podName, podNamespace string) error {
	pod := corev1.Pod{}
	podReady := func(ctx context.Context) error {
		if err := c.Get(ctx, k8sclient.ObjectKey{Name: podName, Namespace: podNamespace}, &pod); err != nil {
			return err
		}
		if !IsPodReady(&pod.Status) {
			return fmt.Errorf("pod %s is not ready yet", podName)
		}
		if pod.Status.PodIP == "" {
			return fmt.Errorf("pod %s has no IP yet", podName)
		}
		return nil
	}
	if err := wait.WaitForSuccessContext(ctx, "Check Server Pod Readiness", wait.WaitingLong, podReady); err != nil {
		return fmt.Errorf("unable to ensure pod readiness: %v", err)
	}
	return nil
}

func IsPodReady(status *corev1.PodStatus) bool {
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
	logs, err := io.ReadAll(podLogs)
	if err != nil {
		return "", fmt.Errorf("failed to read logs for pod %s: %v", podName, err)
	}

	return string(logs), nil
}

// DeleteAndWait deletes a Kubernetes object and waits for it to be removed.
func DeleteAndWait(ctx context.Context, cl k8sclient.Client, obj k8sclient.Object) error {
	if err := DeleteIfExists(ctx, cl, obj); err != nil {
		return err
	}
	return WaitForDeletion(ctx, cl, obj)
}

// DeleteIfExists deletes a Kubernetes object, ignoring "not found" errors.
func DeleteIfExists(ctx context.Context, cl k8sclient.Client, obj k8sclient.Object) error {
	gvks, _, err := cl.Scheme().ObjectKinds(obj)
	if err != nil {
		return fmt.Errorf("failed to get object kinds: %v", err)
	}
	objKind := gvks[0].Kind
	objKey := k8sclient.ObjectKeyFromObject(obj)

	if err := cl.Delete(ctx, obj); err != nil {
		if apierrors.IsNotFound(err) {
			return nil
		}
		return fmt.Errorf("failed to delete %s %s: %v", objKind, objKey, err)
	}
	klog.Infof("%s %s deleted successfully", objKind, objKey)
	return nil
}

// WaitForDeletion deletes a Kubernetes object and wait for it to be deleted.
func WaitForDeletion(ctx context.Context, cl k8sclient.Client, obj k8sclient.Object) error {
	gvks, _, err := cl.Scheme().ObjectKinds(obj)
	if err != nil {
		return fmt.Errorf("failed to get object kinds: %v", err)
	}
	objKind := gvks[0].Kind
	objKey := k8sclient.ObjectKeyFromObject(obj)
	return wait.WaitForSuccessContext(ctx, fmt.Sprintf("Wait for %s deletion", objKind), wait.WaitingMedium, func(ctx context.Context) error {
		newObj := obj.DeepCopyObject().(k8sclient.Object)
		err := cl.Get(ctx, objKey, newObj)
		if err != nil {
			if apierrors.IsNotFound(err) {
				return nil
			}
			return err
		}
		klog.Infof("%s %s still exists, retrying", objKind, objKey)
		return fmt.Errorf("%s %s is still present", objKind, objKey)
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

// Node specfies a node name and its IP address.
type Node struct {
	Name string
	IP   string
}

func GetRequiredNumberOfNodesByLabel(ctx context.Context, cl k8sclient.Client, labelKey string, required int) ([]Node, error) {
	if required <= 0 {
		return nil, fmt.Errorf("required number of nodeIPs is %v", required)
	}
	nodeList, err := GetNodeListByLabel(ctx, cl, labelKey)
	if err != nil {
		return nil, err
	}
	var nodes []Node
	for _, node := range nodeList.Items {
		idx := slices.IndexFunc(node.Status.Addresses, func(addr corev1.NodeAddress) bool {
			return addr.Type == corev1.NodeInternalIP
		})
		if idx == -1 {
			continue
		}
		nodes = append(nodes, Node{
			Name: node.Name,
			IP:   node.Status.Addresses[idx].Address,
		})
		if len(nodes) == required {
			break
		}
	}
	if len(nodes) < required {
		return nil, fmt.Errorf("required number of nodes: %v less than available number of nodes: %v with label: %s", required, len(nodes), labelKey)
	}
	return nodes, nil
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

func NewSSHConnectionAgainstBootstapper(ctx context.Context, cl k8sclient.Client) (*ssh.Client, error) {
	kubeconfig := os.Getenv("KUBECONFIG")
	directory := filepath.Dir(kubeconfig)
	bootstrapperIP, err := extractBootstrapperIPFromFile(directory)
	privateKeyPath := fmt.Sprintf("%s/id_rsa", directory)

	if err != nil {
		return nil, err
	}
	// Read the private key.
	privateKey, err := os.ReadFile(privateKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read private key: %v", err)
	}

	// Create the signer from the private key.
	signer, err := ssh.ParsePrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %v", err)
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
	sshConnection, err := ssh.Dial("tcp", net.JoinHostPort(bootstrapperIP, "22"), config)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to SSH server: %v", err)
	}
	return sshConnection, nil
}

func ExecuteCommandFromBootstapper(ctx context.Context, cl k8sclient.Client, command string) (string, error) {
	client, err := NewSSHConnectionAgainstBootstapper(ctx, cl)
	if err != nil {
		return "", err
	}
	defer client.Close()

	// Create a new SSH session.
	session, err := client.NewSession()
	if err != nil {
		return "", fmt.Errorf("failed to create SSH session: %v", err)
	}
	defer session.Close()

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

func ExecuteNonBlockingCommandFromBootstapper(ctx context.Context, cl k8sclient.Client, command string) (func(client *ssh.Client, session *ssh.Session) error, *ssh.Client, *ssh.Session, error) {
	client, err := NewSSHConnectionAgainstBootstapper(ctx, cl)
	if err != nil {
		return nil, nil, nil, err
	}

	// Create a new SSH session.
	session, err := client.NewSession()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to create SSH session: %v", err)
	}

	// Execute the command.
	err = session.Start(command)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to execute command: %v", err)
	}

	closeConnectionFunc := func(client *ssh.Client, session *ssh.Session) error {
		err := client.Close()
		if err != nil {
			return err
		}
		err = session.Close()
		return err
	}
	return closeConnectionFunc, client, session, nil
}

func RetriveFileFromBootstapper(ctx context.Context, cl k8sclient.Client, remotePath string, localPath string) error {
	sshConnection, err := NewSSHConnectionAgainstBootstapper(ctx, cl)
	if err != nil {
		return err
	}
	defer sshConnection.Close()
	// Create SFTP client from the SSH connection
	sftpClient, err := sftp.NewClient(sshConnection)
	if err != nil {
		return fmt.Errorf("failed to create SFTP client: %w", err)
	}
	defer sftpClient.Close()
	remoteFile, err := sftpClient.Open(remotePath)
	if err != nil {
		return fmt.Errorf("failed to open remote file '%s' via SFTP: %w", remotePath, err)
	}
	defer remoteFile.Close()
	localFile, err := os.Create(localPath)
	if err != nil {
		return fmt.Errorf("failed to create local file '%s': %w", localPath, err)
	}
	defer localFile.Close()

	klog.Infof("Starting file transfer from remote '%s' to local '%s'...", remotePath, localPath)
	bytesCopied, err := io.Copy(localFile, remoteFile)
	if err != nil {
		// If localFile.Close() or remoteFile.Close() fails, it might shadow this error
		// Consider more sophisticated error handling for production if needed
		_ = localFile.Close()    // Attempt to close to flush, ignore error here
		_ = os.Remove(localPath) // Clean up partially written file
		return fmt.Errorf("failed to copy file content from SFTP: %w", err)
	}
	klog.Infof("Successfully transferred %d bytes from bootstrapper:%s to localhost:%s",
		bytesCopied, remotePath, localPath)
	return nil
}

func RunCurlFromBootstrapper(ctx context.Context, cl k8sclient.Client, targetIP string, port int32, retryConfig wait.Waiting) error {
	// Construct the command.
	curlExecuted := func(ctx context.Context) error {
		command := fmt.Sprintf("curl -v http://%s:%d", targetIP, port)
		output, err := ExecuteCommandFromBootstapper(ctx, cl, command)
		if err != nil {
			return fmt.Errorf("failed to execute curl command: %v, output: %s", err, output)
		}

		if !strings.Contains(output, "HTTP/1.1 200 OK") {
			return fmt.Errorf("unexpected curl response: %s", output)
		}

		klog.Infof("Curl command successful from bootstapper to %s:%d", targetIP, port)
		return nil
	}
	klog.Infof("Attempting curl from bootstrapper to %s:%d with retry config: Wait=%v, Every=%v, Timeout=%v",
		targetIP, port, retryConfig.Wait, retryConfig.Every, retryConfig.Timeout)
	curlErr := wait.WaitForSuccessContext(ctx, "Waiting for curl success from bootstrapper", retryConfig, curlExecuted)
	if curlErr != nil {
		// Try again with http0.9
		curlExecuted0_9 := func(ctx context.Context) error {
			command := fmt.Sprintf("curl -v --http0.9 http://%s:%d", targetIP, port)
			output, err := ExecuteCommandFromBootstapper(ctx, cl, command)
			if err != nil {
				return fmt.Errorf("failed to execute curl command: %v, output: %s", err, output)
			}

			if !strings.Contains(output, "200 OK") {
				return fmt.Errorf("unexpected curl response: %s", output)
			}

			klog.Infof("Curl command successful from bootstapper to %s:%d", targetIP, port)
			return nil
		}
		klog.Infof("Attempting curl from bootstrapper with http0.9 to %s:%d with retry config: Wait=%v, Every=%v, Timeout=%v",
			targetIP, port, retryConfig.Wait, retryConfig.Every, retryConfig.Timeout)
		curlErr = wait.WaitForSuccessContext(ctx, "Waiting for curl success from bootstrapper", retryConfig, curlExecuted0_9)
	}
	if curlErr != nil {
		return fmt.Errorf("unable to connect from bootstrapper to %s:%d after retries: %w", targetIP, port, curlErr)
	}
	klog.Infof("Curling from bootstrapper to %s:%d succeed!", targetIP, port)
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

// Get k8s node Info based on label
func GetNodeListByLabel(ctx context.Context, cl k8sclient.Client, labelKey string) (*corev1.NodeList, error) {
	selector, err := metav1.ParseToLabelSelector(labelKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse label selector: %w", err)
	}
	labelSelector, err := metav1.LabelSelectorAsSelector(selector)
	if err != nil {
		return nil, fmt.Errorf("failed to convert label selector: %w", err)
	}
	nodeList := &corev1.NodeList{}
	err = cl.List(ctx, nodeList, &k8sclient.ListOptions{LabelSelector: labelSelector})
	if err != nil {
		return nil, err
	}
	return nodeList, nil
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

// CreateLBService creates a service of type load balancer.
func CreateLBService(ctx context.Context, cl k8sclient.Client, serviceName, serviceNamespace, backendSelector string, servicePort int, targetPort int) error {
	singleStack := corev1.IPFamilyPolicySingleStack
	service := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      serviceName,
			Namespace: serviceNamespace,
			Labels: map[string]string{
				"app": backendSelector,
			},
		},
		Spec: corev1.ServiceSpec{
			IPFamilyPolicy: &singleStack,
			IPFamilies:     []corev1.IPFamily{corev1.IPv4Protocol},
			Ports: []corev1.ServicePort{
				{
					Port:       int32(servicePort),
					Protocol:   corev1.ProtocolTCP,
					TargetPort: intstr.FromInt(int(targetPort)),
				},
			},
			Selector: map[string]string{
				"app": serviceName,
			},
			SessionAffinity: corev1.ServiceAffinityNone,
			Type:            corev1.ServiceTypeLoadBalancer,
		},
	}

	return CreateService(ctx, cl, service)
}

// CreateL2NetworkAndWaitForReady creates L2 network and waits for it to be ready.
func CreateL2NetworkAndWaitForReady(ctx context.Context, cl k8sclient.Client, nc *networkclientset.Clientset, ipamModeExternal gcpnetworkv1.IPAMModeType, networkName, interfaceName string) error {
	networkObject := &gcpnetworkv1.Network{
		ObjectMeta: metav1.ObjectMeta{
			Name: networkName,
		},
		Spec: gcpnetworkv1.NetworkSpec{
			Type:     gcpnetworkv1.L2NetworkType,
			IPAMMode: &ipamModeExternal,
			Gateway4: ptr.To("0.0.0.0"),
			DNSConfig: &gcpnetworkv1.DNSConfig{
				Nameservers: []string{"0.0.0.0"},
			},
			NodeInterfaceMatcher: gcpnetworkv1.NodeInterfaceMatcher{
				InterfaceName: &interfaceName,
			},
			L2NetworkConfig: &gcpnetworkv1.L2NetworkConfig{},
		},
	}

	if _, err := networkutils.CreateNetwork(ctx, nc, networkObject); err != nil {
		if !apierrors.IsAlreadyExists(err) {
			return err
		}
		klog.Warningf("Network %s already exists", networkName)
	}
	klog.Infof("Network %s created successfully", networkName)

	return WaitForNetworkReady(ctx, cl, networkName)
}

func WaitForNetworkReady(ctx context.Context, cl k8sclient.Client, networkName string) error {
	if err := wait.WaitForSuccessContext(ctx, "Wait for network readiness", wait.WaitingMedium, func(ctx context.Context) error {
		network := &gcpnetworkv1.Network{}
		if err := cl.Get(ctx, k8sclient.ObjectKey{Name: networkName}, network); err != nil {
			if apierrors.IsNotFound(err) {
				return fmt.Errorf("network %s not found: %w", networkName, wait.ErrNotRetriable)
			}
			return fmt.Errorf("failed to get network %s: %v", networkName, err)
		}
		if network.Status.Conditions == nil {
			return fmt.Errorf("network %q has no status conditions yet", network.Name)
		}
		condition := meta.FindStatusCondition(network.Status.Conditions, "Ready")
		if condition == nil {
			return fmt.Errorf("network %q does not have a Ready condition yet", network.Name)
		}
		if condition.Status == metav1.ConditionTrue {
			return nil
		}
		return fmt.Errorf("network %q Ready condition is %s (Reason: %s, Message: %s)",
			network.Name, condition.Status, condition.Reason, condition.Message)
	}); err != nil {
		return fmt.Errorf("failed to wait for network readiness: %v", err)
	}
	return nil
}

// --- Upgrade Test Utils ---

const (
	SuccessRateThreshold = 0.75
	ChecksPerPair        = 10
)

// DebugSuite holds all the resources and IPs for the comprehensive test matrix.
type DebugSuite struct {
	CpNode      *corev1.Node
	WorkerNode0 *corev1.Node
	WorkerNode1 *corev1.Node
	CpPod       *corev1.Pod
	WorkerPod0  *corev1.Pod
	WorkerPod1  *corev1.Pod
	HostPod     *corev1.Pod

	// Services per backend
	ClusterIPSvcCP      *corev1.Service
	ClusterIPSvcWorker0 *corev1.Service
	ClusterIPSvcWorker1 *corev1.Service

	NodePortSvcCP      *corev1.Service
	NodePortSvcWorker0 *corev1.Service
	NodePortSvcWorker1 *corev1.Service

	LbSvcCP      *corev1.Service
	LbSvcWorker0 *corev1.Service
	LbSvcWorker1 *corev1.Service

	IperfSvc        *corev1.Service
	IperfDeployment *appsv1.Deployment

	ServerPort int
}

// ConnectivityTestCase defines a single check from a source to a destination.
type ConnectivityTestCase struct {
	SourcePod   string
	TargetAddr  string // Can be an IP or IP:Port
	Protocol    string // "http" or "icmp"
	Description string
	ExpectFail  bool // If true, a failure is considered a success for this test case.
}

// SetupDebugWorkloads sets up the debug workloads and services for the test.
func SetupDebugWorkloads(ctx context.Context, clientset *kubernetes.Clientset, k8sClient k8sclient.Client, namespace string) (*DebugSuite, error) {
	suite := &DebugSuite{}

	// 1. Get Nodes
	klog.Info("Fetching cluster nodes...")
	nodes, err := clientset.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	// We need at least 1 CP and 2 Workers for full coverage, but we'll adapt if fewer.
	// For the purpose of this test, we assume a standard 3-node cluster (1CP, 2Workers) or similar.
	// We'll try to identify them by labels or just take the first ones.
	for _, node := range nodes.Items {
		if _, isCp := node.Labels["node-role.kubernetes.io/control-plane"]; isCp {
			if suite.CpNode == nil {
				n := node
				suite.CpNode = &n
			}
		} else {
			if suite.WorkerNode0 == nil {
				n := node
				suite.WorkerNode0 = &n
			} else if suite.WorkerNode1 == nil {
				n := node
				suite.WorkerNode1 = &n
			}
		}
	}

	// Fallback if we didn't find specific roles (e.g. single node cluster or different labels)
	if suite.CpNode == nil && len(nodes.Items) > 0 {
		n := nodes.Items[0]
		suite.CpNode = &n
	}
	if suite.WorkerNode0 == nil && len(nodes.Items) > 1 {
		n := nodes.Items[1]
		suite.WorkerNode0 = &n
	}
	if suite.WorkerNode1 == nil && len(nodes.Items) > 2 {
		n := nodes.Items[2]
		suite.WorkerNode1 = &n
	}
	// If we still don't have enough workers, reuse what we have to avoid nil pointers,
	// though some tests might be redundant.
	if suite.WorkerNode0 == nil {
		suite.WorkerNode0 = suite.CpNode
	}
	if suite.WorkerNode1 == nil {
		suite.WorkerNode1 = suite.WorkerNode0
	}

	// Generate random server port
	suite.ServerPort = 10000 + int(time.Now().UnixNano()%20000)
	klog.Infof("Using random server port: %d", suite.ServerPort)

	// 2. Create Debug Pods (agnhost/toolbox) on specific nodes
	klog.Info("Ensuring debug pods exist...")
	// We want:
	// - 1 Pod on CP (Pod Network)
	// - 1 Pod on Worker0 (Pod Network)
	// - 1 Pod on Worker1 (Pod Network)
	// - 1 Pod on CP (Host Network)

	serverContainer := corev1.Container{
		Name:  "echo",
		Image: "gcr.io/anthos-networking-ci/toolbox:wora-test",
		Command: []string{"/bin/bash", "-c",
			fmt.Sprintf(`python3 -c 'import http.server, socketserver, socket;
class ThreadingHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer): pass
class H(http.server.BaseHTTPRequestHandler):
 def do_GET(s):
  s.send_response(200);
  s.end_headers();
  s.wfile.write(socket.gethostname().encode())
ThreadingHTTPServer(("", %d), H).serve_forever()'`, suite.ServerPort),
		},
		Ports: []corev1.ContainerPort{{ContainerPort: int32(suite.ServerPort), Protocol: corev1.ProtocolTCP}},
	}

	// Define pod specs
	type podSpec struct {
		Name          string
		Node          *corev1.Node
		HostNetwork   bool
		Labels        map[string]string
		Command       []string
		Image         string
		Ports         []corev1.ContainerPort
		ContainerName string
	}

	specs := []podSpec{
		{
			Name: CpPodName, Node: suite.CpNode,
			Labels:  map[string]string{"app": CpPodName},
			Command: serverContainer.Command, Image: serverContainer.Image, Ports: serverContainer.Ports,
			ContainerName: "echo",
		},
		{
			Name: WorkerPod0Name, Node: suite.WorkerNode0,
			Labels: map[string]string{
				"networking.private.gdc.goog/infra-access": "enabled",
				"app": WorkerPod0Name,
			},
			Command: serverContainer.Command, Image: serverContainer.Image, Ports: serverContainer.Ports,
			ContainerName: "echo",
		},
		{
			Name: WorkerPod1Name, Node: suite.WorkerNode1,
			Labels:  map[string]string{"app": WorkerPod1Name},
			Command: serverContainer.Command, Image: serverContainer.Image, Ports: serverContainer.Ports,
			ContainerName: "echo",
		},
		{
			Name: HostPodName, Node: suite.CpNode, HostNetwork: true,
			Labels:  map[string]string{"app": HostPodName},
			Command: serverContainer.Command, Image: serverContainer.Image, Ports: serverContainer.Ports,
			ContainerName: "echo",
		},
		{
			Name: IperfPodName, Node: suite.WorkerNode0, Labels: map[string]string{"app": "iperf-server"},
			Command: []string{"iperf3", "-s"}, Image: "gcr.io/anthos-networking-ci/toolbox:wora-test",
			Ports:         []corev1.ContainerPort{{ContainerPort: IperfPort, Protocol: corev1.ProtocolTCP}},
			ContainerName: "iperf-server",
		},
	}

	// Helper to create pod using existing CreatePod function
	var wg sync.WaitGroup
	errChan := make(chan error, len(specs))

	for _, spec := range specs {
		wg.Add(1)
		go func(s podSpec) {
			defer wg.Done()

			opts := []PodCustomization{
				WithNodeName(s.Node.Name),
			}
			if s.HostNetwork {
				opts = append(opts, WithHostNetworking())
			}
			for k, v := range s.Labels {
				opts = append(opts, WithLabel(k, v))
			}

			container := corev1.Container{
				Name:            s.ContainerName,
				Image:           s.Image,
				Command:         s.Command,
				Ports:           s.Ports,
				ImagePullPolicy: corev1.PullIfNotPresent,
			}
			opts = append(opts, WithContainers([]corev1.Container{container}))

			// We ignore the cleanup function as we handle cleanup via namespace deletion
			if _, err := CreatePod(ctx, k8sClient, s.Name, namespace, opts...); err != nil {
				errChan <- fmt.Errorf("failed to create pod %s: %v", s.Name, err)
			}
		}(spec)
	}

	wg.Wait()
	close(errChan)

	if len(errChan) > 0 {
		var errs []string
		for err := range errChan {
			errs = append(errs, err.Error())
		}
		return nil, fmt.Errorf("failed to create debug pods: %s", strings.Join(errs, "; "))
	}

	// 3. Create Services
	klog.Info("Ensuring debug services exist...")

	// Define service specs
	type serviceSpec struct {
		Name       string
		Type       corev1.ServiceType
		Port       int32
		Selector   map[string]string
		TargetPort intstr.IntOrString
	}

	svcSpecs := []serviceSpec{
		// CP Services
		{Name: "service-clusterip-cp", Type: corev1.ServiceTypeClusterIP, Port: ClusterIPSvcPort, Selector: map[string]string{"app": CpPodName}, TargetPort: intstr.FromInt(suite.ServerPort)},
		{Name: "service-nodeport-cp", Type: corev1.ServiceTypeNodePort, Port: int32(suite.ServerPort), Selector: map[string]string{"app": CpPodName}, TargetPort: intstr.FromInt(suite.ServerPort)},
		{Name: "service-lb-cp", Type: corev1.ServiceTypeLoadBalancer, Port: LbSvcPort, Selector: map[string]string{"app": CpPodName}, TargetPort: intstr.FromInt(suite.ServerPort)},

		// Worker0 Services
		{Name: "service-clusterip-worker0", Type: corev1.ServiceTypeClusterIP, Port: ClusterIPSvcPort, Selector: map[string]string{"app": WorkerPod0Name}, TargetPort: intstr.FromInt(suite.ServerPort)},
		{Name: "service-nodeport-worker0", Type: corev1.ServiceTypeNodePort, Port: int32(suite.ServerPort), Selector: map[string]string{"app": WorkerPod0Name}, TargetPort: intstr.FromInt(suite.ServerPort)},
		{Name: "service-lb-worker0", Type: corev1.ServiceTypeLoadBalancer, Port: LbSvcPort, Selector: map[string]string{"app": WorkerPod0Name}, TargetPort: intstr.FromInt(suite.ServerPort)},

		// Worker1 Services
		{Name: "service-clusterip-worker1", Type: corev1.ServiceTypeClusterIP, Port: ClusterIPSvcPort, Selector: map[string]string{"app": WorkerPod1Name}, TargetPort: intstr.FromInt(suite.ServerPort)},
		{Name: "service-nodeport-worker1", Type: corev1.ServiceTypeNodePort, Port: int32(suite.ServerPort), Selector: map[string]string{"app": WorkerPod1Name}, TargetPort: intstr.FromInt(suite.ServerPort)},
		{Name: "service-lb-worker1", Type: corev1.ServiceTypeLoadBalancer, Port: LbSvcPort, Selector: map[string]string{"app": WorkerPod1Name}, TargetPort: intstr.FromInt(suite.ServerPort)},

		// Iperf Service
		{Name: IperfSvcName, Type: corev1.ServiceTypeClusterIP, Port: IperfPort, Selector: map[string]string{"app": "iperf-server"}, TargetPort: intstr.FromInt(IperfPort)},
	}

	// Helper to create service
	createService := func(spec serviceSpec) (*corev1.Service, error) {
		svc := &corev1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name:      spec.Name,
				Namespace: namespace,
				Labels:    spec.Selector,
			},
			Spec: corev1.ServiceSpec{
				Selector: spec.Selector,
				Type:     spec.Type,
				Ports: []corev1.ServicePort{
					{
						Port:       spec.Port,
						TargetPort: spec.TargetPort,
					},
				},
			},
		}
		if err := CreateService(ctx, k8sClient, svc); err != nil {
			return nil, err
		}
		return svc, nil
	}

	for _, spec := range svcSpecs {
		svc, err := createService(spec)
		if err != nil {
			return nil, err
		}
		switch spec.Name {
		case "service-clusterip-cp":
			suite.ClusterIPSvcCP = svc
		case "service-nodeport-cp":
			suite.NodePortSvcCP = svc
		case "service-lb-cp":
			suite.LbSvcCP = svc
		case "service-clusterip-worker0":
			suite.ClusterIPSvcWorker0 = svc
		case "service-nodeport-worker0":
			suite.NodePortSvcWorker0 = svc
		case "service-lb-worker0":
			suite.LbSvcWorker0 = svc
		case "service-clusterip-worker1":
			suite.ClusterIPSvcWorker1 = svc
		case "service-nodeport-worker1":
			suite.NodePortSvcWorker1 = svc
		case "service-lb-worker1":
			suite.LbSvcWorker1 = svc
		case IperfSvcName:
			suite.IperfSvc = svc
		}
	}

	// 5. Wait for readiness and collect IPs
	klog.Info("Waiting for resources to become ready, collecting IPs, and verifying scheduling...")

	// Refresh pod info to get IPs
	for _, spec := range specs {
		pod, err := clientset.CoreV1().Pods(namespace).Get(ctx, spec.Name, metav1.GetOptions{})
		if err != nil {
			return nil, err
		}
		switch spec.Name {
		case CpPodName:
			suite.CpPod = pod
			if suite.CpPod.Spec.NodeName != suite.CpNode.Name {
				return nil, fmt.Errorf("cpPod scheduled on %s, expected %s", suite.CpPod.Spec.NodeName, suite.CpNode.Name)
			}
		case WorkerPod0Name:
			suite.WorkerPod0 = pod
			if suite.WorkerPod0.Spec.NodeName != suite.WorkerNode0.Name {
				return nil, fmt.Errorf("workerPod0 scheduled on %s, expected %s", suite.WorkerPod0.Spec.NodeName, suite.WorkerNode0.Name)
			}
		case WorkerPod1Name:
			suite.WorkerPod1 = pod
			if suite.WorkerPod1.Spec.NodeName != suite.WorkerNode1.Name {
				return nil, fmt.Errorf("workerPod1 scheduled on %s, expected %s", suite.WorkerPod1.Spec.NodeName, suite.WorkerNode1.Name)
			}
		case HostPodName:
			suite.HostPod = pod
			if suite.HostPod.Spec.NodeName != suite.CpNode.Name {
				return nil, fmt.Errorf("hostPod scheduled on %s, expected %s", suite.HostPod.Spec.NodeName, suite.CpNode.Name)
			}
		}
	}

	// Wait for LB IPs
	klog.Info("Waiting for LoadBalancer IPs...")
	if err := WaitForServiceReadiness(ctx, k8sClient, "service-lb-cp", namespace, corev1.ServiceTypeLoadBalancer); err != nil {
		return nil, err
	}
	if err := WaitForServiceReadiness(ctx, k8sClient, "service-lb-worker0", namespace, corev1.ServiceTypeLoadBalancer); err != nil {
		return nil, err
	}
	if err := WaitForServiceReadiness(ctx, k8sClient, "service-lb-worker1", namespace, corev1.ServiceTypeLoadBalancer); err != nil {
		return nil, err
	}

	// Refresh LB services to get Status
	lbCP, _ := clientset.CoreV1().Services(namespace).Get(ctx, "service-lb-cp", metav1.GetOptions{})
	suite.LbSvcCP = lbCP
	lbW0, _ := clientset.CoreV1().Services(namespace).Get(ctx, "service-lb-worker0", metav1.GetOptions{})
	suite.LbSvcWorker0 = lbW0
	lbW1, _ := clientset.CoreV1().Services(namespace).Get(ctx, "service-lb-worker1", metav1.GetOptions{})
	suite.LbSvcWorker1 = lbW1

	// Get NodePorts
	klog.Info("Waiting for NodePort services...")
	if err, _ := NodePortReadiness(ctx, k8sClient, "service-nodeport-cp", namespace, corev1.ServiceTypeNodePort); err != nil {
		return nil, err
	}
	if err, _ := NodePortReadiness(ctx, k8sClient, "service-nodeport-worker0", namespace, corev1.ServiceTypeNodePort); err != nil {
		return nil, err
	}
	if err, _ := NodePortReadiness(ctx, k8sClient, "service-nodeport-worker1", namespace, corev1.ServiceTypeNodePort); err != nil {
		return nil, err
	}

	// Refresh NodePort services
	npCP, _ := clientset.CoreV1().Services(namespace).Get(ctx, "service-nodeport-cp", metav1.GetOptions{})
	suite.NodePortSvcCP = npCP
	npW0, _ := clientset.CoreV1().Services(namespace).Get(ctx, "service-nodeport-worker0", metav1.GetOptions{})
	suite.NodePortSvcWorker0 = npW0
	npW1, _ := clientset.CoreV1().Services(namespace).Get(ctx, "service-nodeport-worker1", metav1.GetOptions{})
	suite.NodePortSvcWorker1 = npW1
	klog.Infof("Services are ready")

	return suite, nil
}

const (
	// Resource Names
	CpPodName        = "test-cpnode-0"
	WorkerPod0Name   = "test-worker-node0"
	WorkerPod1Name   = "test-worker-node1"
	HostPodName      = "test-cpnode-host"
	IperfPodName     = "test-iperf-server"
	ClusterIPSvcName = "test-clusterip"
	LbSvcName        = "test-loadbalancer"
	NodePortSvcName  = "test-nodeport"
	IperfSvcName     = "test-iperf-svc"

	// Ports
	LbSvcPort        = 48083
	ClusterIPSvcPort = 58083
	IperfPort        = 5201
)

func RandomString(n int) string {
	var letters = []rune("abcdefghijklmnopqrstuvwxyz0123456789")
	b := make([]rune, n)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

// ConnectivityResult represents a single test result.
type ConnectivityResult struct {
	Timestamp   time.Time `json:"timestamp"`
	Index       uint64    `json:"index"`
	Status      string    `json:"status"`
	Source      string    `json:"source"`
	Target      string    `json:"target"`
	Type        string    `json:"type"`
	Description string    `json:"description"`
	Note        string    `json:"note"`
	Details     string    `json:"details"`
}

// ResultWriter listens on a channel and writes JSON lines to a file.
func ResultWriter(ctx context.Context, wg *sync.WaitGroup, w io.Writer, ch <-chan ConnectivityResult) {
	defer wg.Done()
	encoder := json.NewEncoder(w)
	for result := range ch {
		if err := encoder.Encode(result); err != nil {
			klog.Errorf("Failed to encode result: %v", err)
		}
	}
}

func RunTestPhase(fs afero.Fs, ctx context.Context, namespace, description string, debugInfo *DebugSuite, checkStrictEgressPolicy bool, bootstrapperIP string) error {
	klog.Infof("Starting tests for: %s", description)
	var checkWg sync.WaitGroup
	var httpIndex, icmpIndex uint64
	concurrencyLimit := make(chan struct{}, 30)

	// Generate random result filenames
	httpFile, err := afero.TempFile(fs, "", "http_connectivity_results_*.log")
	if err != nil {
		return fmt.Errorf("failed to create http result file: %v", err)
	}
	defer fs.Remove(httpFile.Name())
	defer httpFile.Close()
	httpResultFile := httpFile.Name()

	icmpFile, err := afero.TempFile(fs, "", "icmp_connectivity_results_*.log")
	if err != nil {
		return fmt.Errorf("failed to create icmp result file: %v", err)
	}
	defer fs.Remove(icmpFile.Name())
	defer icmpFile.Close()
	icmpResultFile := icmpFile.Name()

	iperfFile, err := afero.TempFile(fs, "", "iperf_connectivity_results_*.log")
	if err != nil {
		return fmt.Errorf("failed to create iperf result file: %v", err)
	}
	defer fs.Remove(iperfFile.Name())
	defer iperfFile.Close()
	iperfResultFile := iperfFile.Name()

	klog.Infof("Generated result files: %s, %s, %s", httpResultFile, icmpResultFile, iperfResultFile)

	httpResultsCh := make(chan ConnectivityResult, 100)
	icmpResultsCh := make(chan ConnectivityResult, 100)
	var writerWg sync.WaitGroup

	writerWg.Add(2)
	go ResultWriter(ctx, &writerWg, httpFile, httpResultsCh)
	go ResultWriter(ctx, &writerWg, icmpFile, icmpResultsCh)

	// Launch continuous iperf check in the background.
	checkWg.Add(1)
	go RunIperfCheck(ctx, &checkWg, namespace, debugInfo.CpPod.Name, debugInfo.IperfSvc.Spec.ClusterIP, iperfFile)

	nodeIP := func(node *corev1.Node) string {
		for _, addr := range node.Status.Addresses {
			if addr.Type == corev1.NodeInternalIP {
				return addr.Address
			}
		}
		return ""
	}
	var allTestCases []ConnectivityTestCase

	universalTestCases := []ConnectivityTestCase{
		{TargetAddr: fmt.Sprintf("%s:%d", nodeIP(debugInfo.CpNode), debugInfo.ServerPort), Protocol: "http", Description: "hostnetwork-pod"},
		{TargetAddr: fmt.Sprintf("%s:%d", debugInfo.CpPod.Status.PodIP, debugInfo.ServerPort), Protocol: "http", Description: "pod-network-cp"},
		{TargetAddr: fmt.Sprintf("%s:%d", debugInfo.WorkerPod0.Status.PodIP, debugInfo.ServerPort), Protocol: "http", Description: "pod-network-worker0"},
		{TargetAddr: fmt.Sprintf("%s:%d", debugInfo.WorkerPod1.Status.PodIP, debugInfo.ServerPort), Protocol: "http", Description: "pod-network-worker1"},

		// LB Services
		{TargetAddr: fmt.Sprintf("%s:%d", debugInfo.LbSvcCP.Status.LoadBalancer.Ingress[0].IP, LbSvcPort), Protocol: "http", Description: "service-lb-cp"},
		{TargetAddr: fmt.Sprintf("%s:%d", debugInfo.LbSvcWorker0.Status.LoadBalancer.Ingress[0].IP, LbSvcPort), Protocol: "http", Description: "service-lb-worker0"},
		{TargetAddr: fmt.Sprintf("%s:%d", debugInfo.LbSvcWorker1.Status.LoadBalancer.Ingress[0].IP, LbSvcPort), Protocol: "http", Description: "service-lb-worker1"},

		// ClusterIP Services
		{TargetAddr: fmt.Sprintf("%s:%d", debugInfo.ClusterIPSvcCP.Spec.ClusterIP, ClusterIPSvcPort), Protocol: "http", Description: "service-clusterip-cp"},
		{TargetAddr: fmt.Sprintf("%s:%d", debugInfo.ClusterIPSvcWorker0.Spec.ClusterIP, ClusterIPSvcPort), Protocol: "http", Description: "service-clusterip-worker0"},
		{TargetAddr: fmt.Sprintf("%s:%d", debugInfo.ClusterIPSvcWorker1.Spec.ClusterIP, ClusterIPSvcPort), Protocol: "http", Description: "service-clusterip-worker1"},

		// NodePort Services (via ClusterIP for now, or NodeIP:NodePort)
		// We usually test NodePort via NodeIP:NodePort
		{TargetAddr: fmt.Sprintf("%s:%d", debugInfo.NodePortSvcCP.Spec.ClusterIP, debugInfo.ServerPort), Protocol: "http", Description: "service-nodeport-clusterip-cp"},

		// ICMP
		{TargetAddr: nodeIP(debugInfo.CpNode), Protocol: "icmp", Description: "ping-cp-node"},
		{TargetAddr: nodeIP(debugInfo.WorkerNode0), Protocol: "icmp", Description: "ping-worker0-node"},
		{TargetAddr: nodeIP(debugInfo.WorkerNode1), Protocol: "icmp", Description: "ping-worker1-node"},
		{TargetAddr: debugInfo.CpPod.Status.PodIP, Protocol: "icmp", Description: "ping-cp-pod"},
		{TargetAddr: debugInfo.WorkerPod0.Status.PodIP, Protocol: "icmp", Description: "ping-worker0-pod"},
		{TargetAddr: debugInfo.WorkerPod1.Status.PodIP, Protocol: "icmp", Description: "ping-worker1-pod"},
	}
	allTestCases = append(allTestCases, universalTestCases...)

	unrestrictedSources := []string{CpPodName, WorkerPod0Name, HostPodName, WorkerPod1Name}
	allNodes := []*corev1.Node{debugInfo.CpNode, debugInfo.WorkerNode0, debugInfo.WorkerNode1}

	// NodePort tests: Test each NodePort service via each Node IP
	nodePortServices := []struct {
		Svc         *corev1.Service
		Name        string
		BackendNode *corev1.Node
	}{
		{debugInfo.NodePortSvcCP, "cp", debugInfo.CpNode},
		{debugInfo.NodePortSvcWorker0, "worker0", debugInfo.WorkerNode0},
		{debugInfo.NodePortSvcWorker1, "worker1", debugInfo.WorkerNode1},
	}

	sourceNodeMap := map[string]*corev1.Node{
		CpPodName:      debugInfo.CpNode,
		WorkerPod0Name: debugInfo.WorkerNode0,
		HostPodName:    debugInfo.CpNode,
		WorkerPod1Name: debugInfo.WorkerNode1,
	}

	for _, source := range unrestrictedSources {
		for _, destNode := range allNodes {
			for _, svc := range nodePortServices {
				nodePort := svc.Svc.Spec.Ports[0].NodePort

				srcNode := sourceNodeMap[source]
				expectFail := false

				// Condition: SourcePod Node == Backend Node AND NodePort Node != SourcePod Node
				// There is a known DSR issue where if the source pod is on the same node as the backend,
				// and the destination node is nodeport on a different node, the connection will fail
				if srcNode.Name == svc.BackendNode.Name && destNode.Name != srcNode.Name {
					expectFail = true
				}

				allTestCases = append(allTestCases, ConnectivityTestCase{
					SourcePod: source, TargetAddr: fmt.Sprintf("%s:%d", nodeIP(destNode), nodePort), Protocol: "http",
					Description: fmt.Sprintf("[NodePort] src:%s->node:%s->dest:%s", source, destNode.Name, svc.Name),
					ExpectFail:  expectFail,
				})
			}
		}
	}

	egressShouldBeBlocked := checkStrictEgressPolicy
	sourcePodsForEgressTest := map[string]bool{
		CpPodName:      egressShouldBeBlocked,
		WorkerPod0Name: !egressShouldBeBlocked,
		WorkerPod1Name: egressShouldBeBlocked,
		HostPodName:    !egressShouldBeBlocked,
	}
	for pod, expectFail := range sourcePodsForEgressTest {
		allTestCases = append(allTestCases, ConnectivityTestCase{
			SourcePod: pod, TargetAddr: bootstrapperIP, Protocol: "icmp", Description: "ping-bootstrapper", ExpectFail: expectFail,
		})
	}

	sourcePodMap := map[string]bool{
		debugInfo.CpPod.Name: true, debugInfo.WorkerPod0.Name: true, debugInfo.WorkerPod1.Name: true, debugInfo.HostPod.Name: true,
	}
	for _, tc := range allTestCases {
		sourcesToRun := sourcePodMap
		if tc.SourcePod != "" {
			sourcesToRun = map[string]bool{tc.SourcePod: true}
		}

		for source := range sourcesToRun {
			klog.Infof("Running test case: %s -> %s (%s)", source, tc.TargetAddr, tc.Description)
			checkWg.Add(1)
			go RunConnectivityCheck(ctx, &checkWg, &httpIndex, &icmpIndex, namespace, source, tc, httpResultsCh, icmpResultsCh, concurrencyLimit, ChecksPerPair)
		}
	}

	checkWg.Wait()
	close(httpResultsCh)
	close(icmpResultsCh)
	writerWg.Wait()
	klog.Infof("All connectivity checks for phase '%s' are complete.", description)

	httpFailureMessages := AnalyzeHttpResults(httpFile)
	icmpFailureMessages := AnalyzeResults(icmpFile, "ICMP")
	iperfTestFailed := AnalyzeIperfResults(iperfFile)

	var errMsgs []string
	if len(httpFailureMessages) > 0 {
		errMsgs = append(errMsgs, fmt.Sprintf("HTTP checks failed in phase '%s':\n- %s", description, strings.Join(httpFailureMessages, "\n- ")))
	}
	if len(icmpFailureMessages) > 0 {
		errMsgs = append(errMsgs, fmt.Sprintf("ICMP checks failed in phase '%s':\n- %s", description, strings.Join(icmpFailureMessages, "\n- ")))
	}
	if iperfTestFailed {
		errMsgs = append(errMsgs, fmt.Sprintf("iperf TCP stream was interrupted during phase '%s'", description))
	}

	if len(errMsgs) > 0 {
		return fmt.Errorf("%s", strings.Join(errMsgs, "\n"))
	}
	return nil
}

func RunConnectivityCheck(ctx context.Context, wg *sync.WaitGroup, httpIndex, icmpIndex *uint64, namespace, sourcePod string, tc ConnectivityTestCase, httpResultsCh, icmpResultsCh chan<- ConnectivityResult, limiter chan struct{}, numChecks int) {
	defer wg.Done()
	for i := 0; i < numChecks; i++ {
		select {
		case <-ctx.Done():
			return
		default:
			var currentIndex uint64
			var resultsCh chan<- ConnectivityResult
			var testCaseSuccess bool
			var details string
			var rawSuccess bool
			var commandDescription string

			limiter <- struct{}{}

			switch tc.Protocol {
			case "http":
				host, portStr, err := net.SplitHostPort(tc.TargetAddr)
				if err != nil {
					klog.Errorf("Failed to split host port %s: %v", tc.TargetAddr, err)
					<-limiter
					continue
				}
				port, _ := strconv.Atoi(portStr)

				opts := CurlOptions{
					SourcePodName:   sourcePod,
					SourceNamespace: namespace,
					TargetIP:        host,
					TargetPort:      port,
					TimeoutSeconds:  10,
					WantFailure:     tc.ExpectFail,
				}

				output, err := RunCurlFromPod(opts)
				<-limiter

				rawSuccess = (err == nil)
				testCaseSuccess = rawSuccess
				if testCaseSuccess {
					details = strings.TrimSpace(output)
				} else {
					details = err.Error()
				}

				commandDescription = fmt.Sprintf("curl http://%s", tc.TargetAddr)
				currentIndex = atomic.AddUint64(httpIndex, 1)
				resultsCh = httpResultsCh

			case "icmp":
				err := RunPingFromPodWithTimeoutLimit(ctx, sourcePod, namespace, tc.TargetAddr, 5)
				<-limiter

				rawSuccess = err == nil
				testCaseSuccess = (rawSuccess != tc.ExpectFail)

				if !testCaseSuccess {
					if err != nil {
						details = err.Error()
					}
				} else {
					details = "ping successful"
				}

				commandDescription = fmt.Sprintf("ping %s", tc.TargetAddr)
				currentIndex = atomic.AddUint64(icmpIndex, 1)
				resultsCh = icmpResultsCh
			default:
				<-limiter
				return
			}

			note := "Expected to succeed"
			if tc.ExpectFail {
				note = "Expected to fail"
			}

			status := "SUCCESS"
			if !testCaseSuccess {
				status = "FAILED"
			}

			klog.V(1).Infof("command %s result %v", commandDescription, rawSuccess)

			resultsCh <- ConnectivityResult{
				Timestamp:   time.Now(),
				Index:       currentIndex,
				Status:      status,
				Source:      sourcePod,
				Target:      tc.TargetAddr,
				Type:        tc.Protocol,
				Description: tc.Description,
				Note:        note,
				Details:     strings.TrimSpace(details),
			}
			time.Sleep(1 * time.Second)
		}
	}
}

func RunIperfCheck(ctx context.Context, wg *sync.WaitGroup, namespace, sourcePod, targetIP string, w io.Writer) {
	defer wg.Done()
	// This runs for 35 seconds, slightly longer than the main check phase.
	command := []string{"iperf3", "-c", targetIP, "-t", "35"}
	stdout, stderr, err := ExecCommandInPod(sourcePod, namespace, "echo", command)

	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			fmt.Fprintf(w, "EXIT_CODE: %d\n", exitErr.ExitCode())
		} else {
			fmt.Fprintln(w, "EXIT_CODE: -1")
		}
	} else {
		fmt.Fprintln(w, "EXIT_CODE: 0")
	}
	fmt.Fprintf(w, "--- STDOUT ---\n%s\n", stdout)
	fmt.Fprintf(w, "--- STDERR ---\n%s\n", stderr)
}

func ExecCommandInPod(podName, namespace, containerName string, command []string) (string, string, error) {
	fullCmd := []string{"exec", podName, "-n", namespace, "-c", containerName, "--"}
	fullCmd = append(fullCmd, command...)
	cmd := exec.Command("kubectl", fullCmd...)
	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	return stdout.String(), stderr.String(), err
}

func AnalyzeIperfResults(file afero.File) bool {
	if _, err := file.Seek(0, 0); err != nil {
		klog.Errorf("could not seek iperf results file: %v", err)
		return true
	}
	content, err := io.ReadAll(file)
	if err != nil {
		klog.Errorf("could not read iperf results file: %v", err)
		return true // Missing file is a failure
	}

	if !strings.Contains(string(content), "EXIT_CODE: 0") {
		klog.Errorf("iperf test failed with a non-zero exit code, indicating interruption. Full output: %s", string(content))
		return true
	}
	if strings.Contains(string(content), "error") || strings.Contains(string(content), "failed") {
		klog.Errorf("iperf test failed with errors in output, indicating interruption. Full output: %s", string(content))
		return true
	}

	klog.Info("iperf test completed successfully without interruptions.")
	return false
}

func AnalyzeHttpResults(file afero.File) []string {
	if _, err := file.Seek(0, 0); err != nil {
		return []string{fmt.Sprintf("could not seek results file: %v", err)}
	}

	successCounts := make(map[string]int)
	totalCounts := make(map[string]int)
	firstFailureLog := make(map[string]string)
	backendsHit := make(map[string]map[string]bool)

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		var result ConnectivityResult
		if err := json.Unmarshal([]byte(line), &result); err != nil {
			klog.Errorf("Failed to unmarshal result: %v", err)
			continue
		}

		key := fmt.Sprintf("%s -> %s (%s)", result.Source, result.Target, result.Description)

		totalCounts[key]++
		if result.Status == "SUCCESS" {
			successCounts[key]++
			if backendsHit[key] == nil {
				backendsHit[key] = make(map[string]bool)
			}
			backendsHit[key][result.Details] = true
		} else {
			if _, ok := firstFailureLog[key]; !ok {
				firstFailureLog[key] = line
			}
		}
	}

	var failureMessages []string
	for key, total := range totalCounts {
		if total == 0 {
			continue
		}
		success := successCounts[key]
		successRate := float64(success) / float64(total)

		if successRate < SuccessRateThreshold {
			msg := fmt.Sprintf("Pair '%s' failed with success rate %.2f%% (%d/%d), below threshold of %.2f%%.", key, successRate*100, success, total, SuccessRateThreshold*100)
			if firstLog, ok := firstFailureLog[key]; ok {
				msg = fmt.Sprintf("%s First failure: %s", msg, firstLog)
			}
			failureMessages = append(failureMessages, msg)
		} else {
			klog.Infof("[HTTP] Pair '%s' had a success rate of %.2f%% (%d/%d) and reached %d unique backends.", key, successRate*100, success, total, len(backendsHit[key]))
		}
	}

	if len(failureMessages) > 0 {
		klog.Errorf("[HTTP] Analysis complete. %d pair(s) fell below the success rate threshold.", len(failureMessages))
	} else {
		klog.Infof("[HTTP] Analysis complete. All pairs met the success rate threshold.")
	}

	return failureMessages
}

func AnalyzeResults(file afero.File, protocol string) []string {
	if _, err := file.Seek(0, 0); err != nil {
		klog.Errorf("could not seek results file for %s: %v", protocol, err)
		return []string{fmt.Sprintf("could not seek results file: %v", err)}
	}

	successCounts := make(map[string]int)
	totalCounts := make(map[string]int)
	firstFailureLog := make(map[string]string)

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		var result ConnectivityResult
		if err := json.Unmarshal([]byte(line), &result); err != nil {
			klog.Errorf("Failed to unmarshal result: %v", err)
			continue
		}

		key := fmt.Sprintf("%s -> %s (%s)", result.Source, result.Target, result.Description)

		totalCounts[key]++
		if result.Status == "SUCCESS" {
			successCounts[key]++
		} else {
			if _, ok := firstFailureLog[key]; !ok {
				firstFailureLog[key] = line
			}
		}
	}

	var failureMessages []string
	for key, total := range totalCounts {
		if total == 0 {
			continue
		}
		success := successCounts[key]
		successRate := float64(success) / float64(total)

		if successRate < SuccessRateThreshold {
			msg := fmt.Sprintf("Pair '%s' failed with success rate %.2f%% (%d/%d), below threshold of %.2f%%.", key, successRate*100, success, total, SuccessRateThreshold*100)
			if firstLog, ok := firstFailureLog[key]; ok {
				msg = fmt.Sprintf("%s First failure: %s", msg, firstLog)
			}
			failureMessages = append(failureMessages, msg)
		} else {
			klog.Infof("[%s] Pair '%s' had a success rate of %.2f%% (%d/%d).", protocol, key, successRate*100, success, total)
		}
	}

	if len(failureMessages) > 0 {
		klog.Errorf("[%s] Analysis complete. %d pair(s) fell below the success rate threshold.", protocol, len(failureMessages))
	} else {
		klog.Infof("[%s] Analysis complete. All pairs met the success rate threshold.", protocol)
	}

	return failureMessages
}

func RemovePodLabel(ctx context.Context, cl k8sclient.Client, object k8sclient.ObjectKey, labelKey string) error {
	pod := &corev1.Pod{}
	err := cl.Get(ctx, object, pod)
	if err != nil {
		return fmt.Errorf("failed to get pod %s: %v", object.Name, err)
	}
	patchBase := pod.DeepCopy()
	delete(pod.Labels, labelKey)
	patch := k8sclient.MergeFrom(patchBase)
	if err := cl.Patch(ctx, pod, patch); err != nil {
		return fmt.Errorf("failed to remove label for pod %s: %v", object.Name, err)
	}
	return nil
}

func AddPodLabel(ctx context.Context, cl k8sclient.Client, object k8sclient.ObjectKey, labels map[string]string) error {
	pod := &corev1.Pod{}
	err := cl.Get(ctx, object, pod)
	if err != nil {
		return fmt.Errorf("failed to get pod %s: %v", object.Name, err)
	}
	patchBase := pod.DeepCopy()
	if pod.Labels == nil {
		pod.Labels = make(map[string]string)
	}
	for labelKey, labelValue := range labels {
		pod.Labels[labelKey] = labelValue
	}
	patch := k8sclient.MergeFrom(patchBase)
	if err := cl.Patch(ctx, pod, patch); err != nil {
		return fmt.Errorf("failed to add label for pod %s", object.Name)
	}
	return nil
}
