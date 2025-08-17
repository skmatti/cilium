package multinic_hostfirewall

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"

	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	ciliumlabels "github.com/cilium/cilium/pkg/labels"
	ciliumapi "github.com/cilium/cilium/pkg/policy/api"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	klog "gke-internal.googlesource.com/syllogi/sanitized-klog/third_party/klogv2"
	"gke-internal.googlesource.com/third_party/cilium/google_test/wora/e2e/pkg/test/utils"
)

func createOrPatchCCNPForNetwork(ctx context.Context, cl k8sclient.Client, name, networkName string, allowedCIDR []ciliumapi.CIDR, allowWorld bool) error {
	fromEntities := ciliumapi.EntitySlice{
		ciliumapi.EntityHost,
		ciliumapi.EntityHealth,
		ciliumapi.EntityKubeAPIServer,
		ciliumapi.EntityRemoteNode,
	}
	if allowWorld {
		fromEntities = append(fromEntities, ciliumapi.EntityWorld)
	}
	klog.Infof("Creating or patching CCNP %s for %s network", name, networkName)
	policyObject := &ciliumv2.CiliumClusterwideNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
	}
	result, err := controllerutil.CreateOrPatch(ctx, cl, policyObject, func() error {
		policyObject.Spec = &ciliumapi.Rule{
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
		return nil
	})
	if err != nil {
		return fmt.Errorf("failed to create or patch CCNP %s: %w", name, err)
	}
	klog.Infof("CCNP %s %s", name, result)
	return nil
}

func fetchPodIPForInterface(ctx context.Context, ns, podName, containerName, interfaceName string) (string, error) {
	if interfaceName == "" {
		return "", fmt.Errorf("empty interface name provided for pod %s/%s", ns, podName)
	}

	ipCmd := fmt.Sprintf("ip -4 addr show %s | grep -oP 'inet \\K[\\d.]+' | head -n 1", interfaceName)
	args := []string{"exec", podName, "-n", ns, "-c", containerName, "--", "/bin/sh", "-c", ipCmd}
	cmd := exec.CommandContext(ctx, "kubectl", args...)
	klog.V(4).Infof("Executing command: kubectl %s", strings.Join(args, " "))

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("kubectl exec failed for interface %q in pod %s/%s: %v. Stderr: %s", interfaceName, ns, podName, err, stderr.String())
	}

	if stderr.Len() > 0 {
		return "", fmt.Errorf("stderr output while getting IP for %q in pod %s/%s: %s", interfaceName, ns, podName, stderr.String())
	}

	ipAddress := strings.TrimSpace(stdout.String())
	if ipAddress == "" {
		return "", fmt.Errorf("no IPv4 address found for interface %q in pod %s/%s", interfaceName, ns, podName)
	}

	klog.Infof("Found IPv4 address for interface %q in pod %s/%s: %s", interfaceName, ns, podName, ipAddress)
	return ipAddress, nil
}

func FetchPodIPsForInterfaces(ctx context.Context, cl k8sclient.Client, ns, name string, interfaceNames []string) ([]string, error) {
	klog.Infof("Fetching IP addresses for interfaces %v in pod %s/%s", interfaceNames, ns, name)
	pod := &corev1.Pod{}
	if err := cl.Get(ctx, k8sclient.ObjectKey{Namespace: ns, Name: name}, pod); err != nil {
		if apierrors.IsNotFound(err) {
			return nil, fmt.Errorf("pod %s/%s not found: %w", ns, name, err)
		}
		return nil, fmt.Errorf("failed to get pod %s/%s: %w", ns, name, err)
	}
	if !utils.IsPodReady(&pod.Status) {
		return nil, fmt.Errorf("pod %s/%s is not ready", ns, name)
	}

	ips := make([]string, len(interfaceNames))
	for i, ifaceName := range interfaceNames {
		ip, err := fetchPodIPForInterface(ctx, ns, name, "responder", ifaceName)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch IP for interface %q at index %d: %w", ifaceName, i, err)
		}
		ips[i] = ip
	}
	klog.Infof("Successfully fetched IPs for interfaces %v in pod %s/%s: %v", interfaceNames, ns, name, ips)
	return ips, nil
}
