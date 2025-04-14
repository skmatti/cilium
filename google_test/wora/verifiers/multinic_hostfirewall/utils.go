package multinic_hostfirewall

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time" // Do not use pkg/time in test code.

	networkv1 "github.com/GoogleCloudPlatform/gke-networking-api/apis/network/v1"
	networkclientset "github.com/GoogleCloudPlatform/gke-networking-api/client/network/clientset/versioned"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	ciliumlabels "github.com/cilium/cilium/pkg/labels"
	ciliumapi "github.com/cilium/cilium/pkg/policy/api"
	. "github.com/onsi/gomega"
	networkutils "gke-internal.googlesource.com/anthos-networking/test-infra/pkg/network"
	klog "gke-internal.googlesource.com/syllogi/sanitized-klog/third_party/klogv2"
	"gke-internal.googlesource.com/third_party/cilium/google_test/wora/e2e/pkg/test/utils"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	k8sclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

const (
	pollInterval           = 5 * time.Second
	networkDeletionTimeout = 5 * time.Minute
	timeout                = 3 * time.Minute
	networkReadyTimeout    = 5 * time.Minute
)

// NetworkStatusAnnotationValue defines the structure within the networkStatusAnnotation
type NetworkStatusAnnotationValue struct {
	Name       string `json:"Name"`
	IPv4Subnet string `json:"IPv4Subnet,omitempty"`
	IPv6Subnet string `json:"IPv6Subnet,omitempty"`
}

var (
	networkStatusAnnotation = "networking.gke.io/network-status"
)

func createOrPatchCCNPForMultinic(ctx context.Context, cl k8sclient.Client, networkPolicyName string, networkName string, allowedCIDR []ciliumapi.CIDR, allowWorld bool) error {
	fromEntities := ciliumapi.EntitySlice{
		ciliumapi.EntityHost,
		ciliumapi.EntityHealth,
		ciliumapi.EntityKubeAPIServer,
		ciliumapi.EntityRemoteNode,
	}
	if allowWorld {
		klog.Infof("Adding EntityWorld to policy %s", networkPolicyName)
		fromEntities = append(fromEntities, ciliumapi.EntityWorld)
	}
	klog.Infof("Creating CCNP %s for network %s", networkPolicyName, networkName)
	policyObject := &ciliumv2.CiliumClusterwideNetworkPolicy{
		TypeMeta: metav1.TypeMeta{
			APIVersion: ciliumv2.SchemeGroupVersion.String(),
			Kind:       "CiliumClusterwideNetworkPolicy",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: networkPolicyName,
		},
	}
	desiredSpec := &ciliumapi.Rule{
		NodeSelector: ciliumapi.NewESFromLabels(
			ciliumlabels.NewLabel(
				"multinic-host",
				networkName,
				ciliumlabels.LabelSourceReserved,
			),
		),
		Ingress: []ciliumapi.IngressRule{
			{
				IngressCommonRule: ciliumapi.IngressCommonRule{
					FromEntities: fromEntities,
				},
			},
			{
				IngressCommonRule: ciliumapi.IngressCommonRule{
					FromCIDR: allowedCIDR,
				},
			},
		},
	}
	result, err := controllerutil.CreateOrPatch(ctx, cl, policyObject, func() error {
		policyObject.Spec = desiredSpec
		return nil
	})
	if err == nil {
		klog.Infof("CCNP %s %s", networkPolicyName, result)
	}
	return err
}

func FetchPodVxlanIPs(ctx context.Context, cl k8sclient.Client, podName, ns string, interfaceNames []string) ([]string, error) {
	klog.Infof("Fetching IP addresses for interfaces %v in pod %s/%s using kubectl exec", interfaceNames, ns, podName)
	pod := &corev1.Pod{}
	err := cl.Get(ctx, k8sclient.ObjectKey{Namespace: ns, Name: podName}, pod)
	if err != nil {
		if apierrors.IsNotFound(err) {
			return nil, fmt.Errorf("pod %s/%s not found: %w", ns, podName, err)
		}
		return nil, fmt.Errorf("failed to get pod %s/%s before exec: %w", ns, podName, err)
	}
	if !utils.IsPodReady(&pod.Status) {
		return nil, fmt.Errorf("pod %s/%s is not ready", ns, podName)
	}

	results := make([]string, len(interfaceNames))

	for i, interfaceName := range interfaceNames {
		if interfaceName == "" {
			return nil, fmt.Errorf("empty interface name provided at index %d for pod %s/%s", i, ns, podName)
		}
		ipCmd := fmt.Sprintf("ip -4 addr show %s | grep -oP 'inet \\K[\\d.]+' | head -n 1", interfaceName)
		args := []string{"exec", podName, "-n", ns, "-c", "responder", "--", "/bin/sh", "-c", ipCmd}
		cmd := exec.CommandContext(ctx, "kubectl", args...)
		klog.V(4).Infof("Executing command: kubectl %s", strings.Join(args, " "))

		var stdout, stderr bytes.Buffer
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr

		execErr := cmd.Run()
		stdoutStr := stdout.String()
		stderrStr := stderr.String()

		if execErr != nil {
			return nil, fmt.Errorf("kubectl exec failed for interface %q in pod %s/%s: %v. Stderr: %s", interfaceName, ns, podName, execErr, stderrStr)
		}

		if stderrStr != "" {
			return nil, fmt.Errorf("Non-fatal stderr output while getting IP for %q in pod %s/%s: %s", interfaceName, ns, podName, stderrStr)
		}
		if stdoutStr == "" {
			return nil, fmt.Errorf("No IPv4 address found/extracted for interface %q in pod %s/%s.", interfaceName, ns, podName)
			results[i] = ""
		} else {
			ipAddress := strings.TrimSpace(stdoutStr)
			if ipAddress == "" {
				return nil, fmt.Errorf("extracted IP address is empty for interface %q in pod %s/%s via kubectl exec (command succeeded but no IP found/extracted)", interfaceName, ns, podName)
			} else {
				klog.Infof("Found IPv4 address for interface %q in pod %s/%s: %s", interfaceName, ns, podName, stdoutStr)
				results[i] = ipAddress
			}
		}
	}
	klog.Infof("Successfully fetched IPs for interfaces %v in pod %s/%s: %v", interfaceNames, ns, podName, results)
	return results, nil
}

// isNetworkReady checks if the Network resource has a Ready condition with status True.
func isNetworkReady(network *networkv1.Network) error {
	if network == nil {
		return fmt.Errorf("Network object is nil, cannot determine readiness")
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
}

func validateNetworkReadiness(ctx context.Context, cl k8sclient.Client, networkName string, nodesToValidate []string) error {
	klog.Infof("Validating if Network %q exists, is Ready, and provisioned on nodes %v", networkName, nodesToValidate)
	retrievedNetwork := &networkv1.Network{}
	var lastErr error

	success := Eventually(ctx, func(g Gomega) error {
		klog.Infof("Polling Network to check readiness %q", networkName)
		getErr := cl.Get(ctx, k8sclient.ObjectKey{Name: networkName}, retrievedNetwork)
		if getErr != nil {
			lastErr = fmt.Errorf("failed to get network %s: %w", networkName, getErr)
			return lastErr
		}
		readyErr := isNetworkReady(retrievedNetwork)
		if readyErr != nil {
			lastErr = fmt.Errorf("network %q not ready: %w", networkName, readyErr)
			return lastErr
		}

		if len(nodesToValidate) > 0 {
			for _, nodeName := range nodesToValidate {
				networkFound, err := doesNetworkExistInNodeAnnotations(ctx, cl, nodeName, networkName)
				if err != nil {
					// Error getting or parsing the annotation
					lastErr = fmt.Errorf("failed to check network annotation on node %s for network %q: %w", nodeName, networkName, err)
					return lastErr // Return error to Eventually
				}
				if !networkFound {
					lastErr = fmt.Errorf("network %q not found in node %s status annotation", networkName, nodeName)
					return lastErr // Return error to Eventually
				}
				klog.Infof("Network %q found in node %s status annotation as expected.", networkName, nodeName)
			}
		}
		lastErr = nil
		klog.Infof("Network %q exists, is Ready, and annotation checks passed for nodes %v.", networkName, nodesToValidate)
		return nil
	}).
		WithTimeout(networkReadyTimeout).
		WithPolling(pollInterval).
		Should(Succeed())

	if !success {
		finalStateMsg := "unavailable"
		if retrievedNetwork.Name != "" {
			finalStateMsg = fmt.Sprintf("ObjectStatus=%+v", retrievedNetwork.Status)
		}
		klog.Errorf("Network %q checks failed within timeout. Final state: %s. Last error: %v", networkName, finalStateMsg, lastErr)
		if lastErr != nil {
			return fmt.Errorf("network %q checks failed within %v timeout: last error: %v", networkName, networkReadyTimeout, lastErr)
		}
		return fmt.Errorf("network %q checks failed within %v timeout", networkName, networkReadyTimeout)
	}

	klog.Infof("Network %q exists, is Ready, and provisioned on nodes %v.", networkName, nodesToValidate)
	return nil
}

func validateCCNPExistence(ctx context.Context, cl k8sclient.Client, networkPolicyName string) error {
	klog.Infof("Validating if the CCNP %s exists", networkPolicyName)
	retrievedPolicy := &ciliumv2.CiliumClusterwideNetworkPolicy{}
	var lastErr error
	err := wait.PollUntilContextTimeout(ctx, pollInterval, timeout, true, func(ctx context.Context) (bool, error) {
		getErr := cl.Get(ctx, k8sclient.ObjectKey{Name: networkPolicyName}, retrievedPolicy)
		if getErr == nil {
			return true, nil
		}
		if apierrors.IsNotFound(getErr) {
			klog.V(4).Infof("CCNP %s not found yet, retrying...", networkPolicyName)
			return false, nil
		}
		lastErr = fmt.Errorf("Error getting CCNP %s (will retry): %v", networkPolicyName, getErr)
		return false, nil
	})

	if err != nil {
		return fmt.Errorf("failed to confirm existence of CCNP %s within %v: %w. Last Error: %w", networkPolicyName, timeout, err, lastErr)
	}

	klog.Infof("CCNP %s exists.", networkPolicyName)
	return nil
}

func deleteAndWaitForNetworkDeletion(ctx context.Context, cl k8sclient.Client, nc *networkclientset.Clientset, networkName string, nodesToCheck []string) error {
	klog.Infof("Attempting to delete Network %s and verify removal from node annotations %v", networkName, nodesToCheck)
	err := networkutils.TeardownNetwork(ctx, nc, networkName)
	if err != nil {
		if apierrors.IsNotFound(err) {
			klog.Infof("Network %s was already deleted before initiating teardown.", networkName)
		} else {
			klog.Errorf("Failed to initiate deletion for Network %s: %v", networkName, err)
		}
	} else {
		klog.Infof("Network %s deletion request sent successfully. Waiting for removal...", networkName)
	}

	var lastErr error
	waitErr := wait.PollUntilContextTimeout(ctx, pollInterval, networkDeletionTimeout, true, func(ctx context.Context) (bool, error) {
		networkExists := true
		getErr := cl.Get(ctx, k8sclient.ObjectKey{Name: networkName}, &networkv1.Network{})
		if getErr != nil {
			if apierrors.IsNotFound(getErr) {
				networkExists = false
				klog.V(4).Infof("Network CRD %s confirmed deleted.", networkName)
			} else {
				lastErr = fmt.Errorf("error checking deletion status for Network CRD %s: %w", networkName, getErr)
				klog.Warningf("%v (will retry)", lastErr)
				return false, nil // Keep polling
			}
		} else {
			lastErr = fmt.Errorf("network CRD %s still exists", networkName)
			klog.V(4).Infof("%v, continuing to wait...", lastErr)
			return false, nil // Keep polling
		}

		// If CRD is gone, proceed to check annotations
		if !networkExists {
			allAnnotationsClean := true
			for _, nodeName := range nodesToCheck {
				networkFound, err := doesNetworkExistInNodeAnnotations(ctx, cl, nodeName, networkName)
				if err != nil {
					return false, fmt.Errorf("failed to check network annotation on node %s for network %q: %w", nodeName, networkName, err)
				}
				if networkFound {
					lastErr = fmt.Errorf("network %q still found in node %s status annotation", networkName, nodeName)
					klog.V(4).Infof("%v, continuing to wait...", lastErr)
					allAnnotationsClean = false // Network entry still present
					break                       // Stop checking other nodes for this poll iteration
				}
			}
			if allAnnotationsClean {
				klog.Infof("Network CRD %s deleted AND annotation checks passed for nodes %v.", networkName, nodesToCheck)
				lastErr = nil
				return true, nil
			}
		}
		return false, nil // Keep polling
	})

	if waitErr != nil {
		klog.Errorf("Failed waiting for Network %s deletion and annotation cleanup: %v", networkName, waitErr)
		if errors.Is(waitErr, context.DeadlineExceeded) || waitErr == wait.ErrWaitTimeout {
			if lastErr != nil {
				return fmt.Errorf("failed waiting for network %s deletion/cleanup within %v (last error: %w): %w", networkName, networkDeletionTimeout, lastErr, waitErr)
			}
			return fmt.Errorf("timed out after %v waiting for network %s deletion/cleanup: %w", networkDeletionTimeout, networkName, waitErr)
		}
		return fmt.Errorf("error occurred while waiting for network %s deletion/cleanup: %w", networkName, waitErr)
	}
	klog.Infof("Successfully deleted Network %s and verified annotation cleanup on nodes %v.", networkName, nodesToCheck)
	return nil
}

func doesNetworkExistInNodeAnnotations(ctx context.Context, cl k8sclient.Client, nodeName string, networkName string) (bool, error) {
	node := &corev1.Node{}
	nodeKey := k8sclient.ObjectKey{Name: nodeName}
	if err := cl.Get(ctx, nodeKey, node); err != nil {
		return false, fmt.Errorf("get node %s: %w", nodeName, err)
	}
	annotationValue, exists := node.Annotations[networkStatusAnnotation]
	if !exists {
		return false, fmt.Errorf("%q annotation not found on node %s", networkStatusAnnotation, nodeName)
	}

	var statusSlice []NetworkStatusAnnotationValue
	if err := json.Unmarshal([]byte(annotationValue), &statusSlice); err != nil {
		return false, fmt.Errorf("unmarshal value %q of key %q from annotations of node %s: %w", annotationValue, networkStatusAnnotation, nodeName, err)
	}
	networkFound := false
	for _, statusEntry := range statusSlice {
		if statusEntry.Name == networkName {
			networkFound = true
			break
		}
	}
	return networkFound, nil
}

// GetAllNodeNames retrieves a list of names for all nodes in the cluster.
func GetAllNodeNames(ctx context.Context, cl k8sclient.Client) ([]string, error) {
	nodeList := &corev1.NodeList{}
	err := cl.List(ctx, nodeList)
	if err != nil {
		return nil, fmt.Errorf("failed to list nodes: %w", err)
	}

	nodeNames := make([]string, 0, len(nodeList.Items))
	for _, node := range nodeList.Items {
		nodeNames = append(nodeNames, node.Name)
	}

	klog.Infof("Found %d nodes: %v", len(nodeNames), nodeNames)
	return nodeNames, nil
}
