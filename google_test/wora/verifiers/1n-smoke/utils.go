package smoke

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes"
	"k8s.io/utils/ptr"
)

const (
	serviceNamespace    = "default"
	serviceName         = "nginx"
	kontrollerNamespace = "kube-system"
	kontrollerName      = "kontroller"
)

func createTestServiceWithNEGs(ctx context.Context, kc kubernetes.Interface) error {
	selector := map[string]string{"app": serviceName}
	var reps int32 = 3

	deployment := appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name: serviceName,
		},
		Spec: appsv1.DeploymentSpec{
			Selector: &metav1.LabelSelector{
				MatchLabels: selector,
			},
			Replicas: &reps,
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: selector,
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:    serviceName,
							Image:   "k8s.gcr.io/e2e-test-images/agnhost:2.41",
							Command: []string{"/agnhost"},
							Args:    []string{"grpc-health-checking", "--port=443", "--http-port=80"},
							Ports: []corev1.ContainerPort{
								{ContainerPort: 80},
								{ContainerPort: 443},
							},
						},
					},
				},
			},
		},
	}
	_, err := kc.AppsV1().Deployments(serviceNamespace).Create(ctx, &deployment, metav1.CreateOptions{})
	if err != nil {
		return err
	}

	service := corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name: serviceName,
			Annotations: map[string]string{
				"cloud.google.com/neg": "{\"exposed_ports\": {\"80\":{}, \"443\":{}}}",
			},
			Labels: map[string]string{
				"networking.gke.io/service-proxy-name": "experimental",
			},
		},
		Spec: corev1.ServiceSpec{
			Selector: selector,
			Ports: []corev1.ServicePort{
				{
					Protocol:   corev1.ProtocolTCP,
					Name:       "http",
					Port:       80,
					TargetPort: intstr.FromInt(80),
				},
				{
					Protocol:   corev1.ProtocolTCP,
					Name:       "https",
					Port:       443,
					TargetPort: intstr.FromInt(443),
				},
			},
		},
	}
	_, err = kc.CoreV1().Services(serviceNamespace).Create(ctx, &service, metav1.CreateOptions{})
	if err != nil {
		return err
	}

	return nil
}

func testServiceReady(ctx context.Context, kc kubernetes.Interface) error {
	return deploymentReady(ctx, kc, serviceNamespace, serviceName)
}

func deleteTestService(ctx context.Context, kc kubernetes.Interface) error {
	return errors.Join(
		kc.CoreV1().Services(serviceNamespace).Delete(ctx, serviceName, metav1.DeleteOptions{}),
		kc.AppsV1().Deployments(serviceNamespace).Delete(ctx, serviceName, metav1.DeleteOptions{}),
	)
}

type kontrollerConfig struct {
	projectID  string
	projectNum string
	mesh       string

	registry string
	tag      string
}

func installKontroller(ctx context.Context, kc kubernetes.Interface, config kontrollerConfig) error {
	configMap := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "kon-metadata",
			Namespace: kontrollerNamespace,
		},
		Data: map[string]string{
			"projectID":     config.projectID,
			"projectNumber": config.projectNum,
			"mesh":          config.mesh,
		},
	}
	_, err := kc.CoreV1().ConfigMaps(kontrollerNamespace).Create(ctx, configMap, metav1.CreateOptions{})
	if err != nil {
		return err
	}

	sa := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      kontrollerName,
			Namespace: kontrollerNamespace,
		},
	}
	_, err = kc.CoreV1().ServiceAccounts(kontrollerNamespace).Create(ctx, sa, metav1.CreateOptions{})
	if err != nil {
		return err
	}

	crb := &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      kontrollerName,
			Namespace: kontrollerNamespace,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      kontrollerName,
				Namespace: kontrollerNamespace,
			},
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     kontrollerName,
		},
	}
	_, err = kc.RbacV1().ClusterRoleBindings().Create(ctx, crb, metav1.CreateOptions{})
	if err != nil {
		return err
	}

	cr := &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			Name:      kontrollerName,
			Namespace: kontrollerNamespace,
		},
		Rules: []rbacv1.PolicyRule{
			{
				Verbs: []string{
					"get",
					"watch",
					"list",
				},
				APIGroups: []string{""},
				Resources: []string{"services"},
			},
		},
	}
	_, err = kc.RbacV1().ClusterRoles().Create(ctx, cr, metav1.CreateOptions{})
	if err != nil {
		return err
	}

	var reps int32 = 1
	selector := map[string]string{"app": kontrollerName}

	deployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      kontrollerName,
			Namespace: kontrollerNamespace,
			Labels:    selector,
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &reps,
			Selector: &metav1.LabelSelector{MatchLabels: selector},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: selector},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:  "one-network-controller",
							Image: fmt.Sprintf("gcr.io/%s/kon:%s", config.registry, config.tag),
							Command: []string{
								"/konctl",
								"td",
								"--mesh",
								"$(MESH)",
								"--project-id",
								"$(PROJECT_ID)",
								"--project-number",
								"$(PROJECT_NUMBER)",
								"--concurrency",
								"1",
							},
							Env: []corev1.EnvVar{
								{
									Name: "MESH",
									ValueFrom: &corev1.EnvVarSource{ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{Name: "kon-metadata"},
										Key:                  "mesh",
									},
									},
								},
								{
									Name: "PROJECT_ID",
									ValueFrom: &corev1.EnvVarSource{ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{Name: "kon-metadata"},
										Key:                  "projectID",
									},
									},
								},
								{
									Name: "PROJECT_NUMBER",
									ValueFrom: &corev1.EnvVarSource{ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{Name: "kon-metadata"},
										Key:                  "projectNumber",
									},
									},
								},
							},
							ImagePullPolicy: corev1.PullPolicy("Always"),
							VolumeMounts: []corev1.VolumeMount{
								{
									Name:      "latency-log-storage",
									MountPath: "/var/log",
								},
							},
						},
					},
					ServiceAccountName: kontrollerName,
					Volumes: []corev1.Volume{
						{
							Name: "latency-log-storage",
							VolumeSource: corev1.VolumeSource{
								EmptyDir: &corev1.EmptyDirVolumeSource{},
							},
						},
					},
					TerminationGracePeriodSeconds: ptr.To[int64](60),
				},
			},
		},
	}
	_, err = kc.AppsV1().Deployments(kontrollerNamespace).Create(ctx, deployment, metav1.CreateOptions{})
	if err != nil {
		return err
	}
	return nil
}

func kontrollerReady(ctx context.Context, kc kubernetes.Interface) error {
	return deploymentReady(ctx, kc, kontrollerNamespace, kontrollerName)
}

func deleteKontroller(ctx context.Context, kc kubernetes.Interface) error {
	return errors.Join(
		kc.AppsV1().Deployments(kontrollerNamespace).Delete(ctx, kontrollerName, metav1.DeleteOptions{}),
		kc.RbacV1().ClusterRoleBindings().Delete(ctx, kontrollerName, metav1.DeleteOptions{}),
		kc.RbacV1().ClusterRoles().Delete(ctx, kontrollerName, metav1.DeleteOptions{}),
		kc.CoreV1().ConfigMaps(kontrollerNamespace).Delete(ctx, "kon-metadata", metav1.DeleteOptions{}),
		kc.CoreV1().ServiceAccounts(kontrollerNamespace).Delete(ctx, kontrollerName, metav1.DeleteOptions{}),
	)
}

func deploymentReady(ctx context.Context, kc kubernetes.Interface, namespace, name string) error {
	deployment, err := kc.AppsV1().Deployments(namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return err
	}
	if got, want := deployment.Status.ReadyReplicas, *deployment.Spec.Replicas; got != want {
		return fmt.Errorf("ready replicas, got=%d, want=%d", got, want)
	}
	return nil
}

func daemonsetReady(ctx context.Context, kc kubernetes.Interface, namespace, name string) error {
	nodes, err := kc.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return err
	}
	if len(nodes.Items) == 0 {
		return fmt.Errorf("no nodes found")
	}
	ds, err := kc.AppsV1().DaemonSets(namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return err
	}
	if got, want := ds.Status.NumberReady, int32(len(nodes.Items)); got != want {
		return fmt.Errorf("ready replicas, got=%d, want=%d", got, want)
	}
	return nil
}

func podDone(ctx context.Context, kc kubernetes.Interface, namespace, name string) error {
	pod, err := kc.CoreV1().Pods(namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return err
	}
	if pod.Status.Phase != corev1.PodSucceeded {
		return fmt.Errorf("pod phase, got=%s, want=%s", pod.Status.Phase, corev1.PodSucceeded)
	}
	return nil
}

func deletePod(ctx context.Context, kc kubernetes.Interface, namespace, name string) error {
	return kc.CoreV1().Pods(namespace).Delete(ctx, name, metav1.DeleteOptions{})
}

func getAnetdIP(ctx context.Context, kc kubernetes.Interface) ([]string, error) {
	pods, err := kc.CoreV1().Pods(ciliumNS).List(ctx, metav1.ListOptions{
		LabelSelector: "k8s-app=cilium",
	})
	if err != nil {
		return nil, fmt.Errorf("error listing anetd pods: %v", err)
	}

	if len(pods.Items) == 0 {
		return nil, fmt.Errorf("got 0 pods, when expected at least 1")
	}

	ret := make([]string, 0)

	for _, pod := range pods.Items {
		if !strings.HasPrefix(pod.Name, "anetd") {
			continue
		}
		if pod.Status.PodIP == "" {
			continue
		}
		ret = append(ret, pod.Status.PodIP)
	}
	if len(ret) == 0 {
		return nil, fmt.Errorf("none of the selected pods had IP assigned to it")
	}
	return ret, nil
}
func getPodName(ctx context.Context, kc kubernetes.Interface, namespace, selector string) (string, error) {
	pods, err := kc.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{
		LabelSelector: selector,
	})
	if err != nil {
		return "", err
	}
	if len(pods.Items) == 0 {
		return "", fmt.Errorf("got 0 pods, when expected at least 1")
	}
	return pods.Items[0].Name, nil
}

func getPodLogs(ctx context.Context, kc kubernetes.Interface, namespace, name string) (string, error) {
	rc, err := kc.CoreV1().Pods(namespace).GetLogs(name, &corev1.PodLogOptions{}).Stream(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to fetch logs: %w", err)
	}
	defer rc.Close()
	var buf bytes.Buffer
	buf.ReadFrom(rc)
	return buf.String(), nil
}

func firewallRuleName(mesh string) string {
	return fmt.Sprintf("allow-healthchecks-%s", mesh)
}
