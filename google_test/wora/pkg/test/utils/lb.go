package utils

import (
	"context"
	"fmt"
	"time"

	"github.com/cenkalti/backoff/v4"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	k8sclient "sigs.k8s.io/controller-runtime/pkg/client"

	klog "gke-internal.googlesource.com/syllogi/sanitized-klog/third_party/klogv2"
)

const (
	kubeSystemNameSpace = "kube-system"
	// maxRetries is the maximum times to retry an operation.
	maxRetries = uint64(10)
	// defaultConstantBackOffTime is the default backoff time for constant
	// backoff.
	defaultConstantBackOffTime = 3 * time.Second
	// defaultInitialInterval defines a the default initial polling interval as
	// 2s.
	defaultInitialInterval = 2 * time.Second
)

var (
	ipAddrPoolGVR = schema.GroupVersionResource{
		Group:    "metallb.io",
		Version:  "v1beta1",
		Resource: "ipaddresspools",
	}
	l2AdvertisementGVR = schema.GroupVersionResource{
		Group:    "metallb.io",
		Version:  "v1beta1",
		Resource: "l2advertisements",
	}
)

// CreateIPAddressPool creates a new metalLB IPAddressPool using the unstructured client.
func CreateIPAddressPool(ctx context.Context, dc dynamic.Interface, ipAddrPoolName string, annotations map[string]string, addresses []string) (*unstructured.Unstructured, error) {
	obj := &unstructured.Unstructured{
		Object: map[string]any{
			"apiVersion": "metallb.io/v1beta1",
			"kind":       "IPAddressPool",
			"metadata": map[string]any{
				"name":        ipAddrPoolName,
				"namespace":   kubeSystemNameSpace,
				"annotations": annotations,
			},
			"spec": map[string]any{
				"addresses":     addresses,
				"autoAssign":    true,
				"avoidBuggyIPs": false,
			},
		},
	}

	var ipAddrPool *unstructured.Unstructured
	var err error

	f := func() error {
		var retErr error
		var creationErr error
		ipAddrPool, creationErr = dc.Resource(ipAddrPoolGVR).Namespace(kubeSystemNameSpace).Create(ctx, obj, metav1.CreateOptions{})
		if creationErr != nil {
			retErr = fmt.Errorf("error creating unstructured ipAddressPool: %v", creationErr)
			klog.Error(retErr)
			return retErr
		}
		return nil
	}

	if err = backoff.Retry(f, backoff.WithMaxRetries(backoff.NewConstantBackOff(defaultConstantBackOffTime), maxRetries)); err != nil {
		klog.Errorf("err creating ipAddressPool after %q retries: %v", maxRetries, err)
		return nil, err
	}

	klog.Infof("IPAddressPool %s/%s created successfully", ipAddrPool.GetNamespace(), ipAddrPool.GetName())
	return ipAddrPool, err
}

// CreateL2Advertisement creates a new metalLB IPAddressPool using the unstructured client.
func CreateL2Advertisement(ctx context.Context, dc dynamic.Interface, l2AdvertisementName string, ipAddrPools []string) (*unstructured.Unstructured, error) {
	obj := &unstructured.Unstructured{
		Object: map[string]any{
			"apiVersion": "metallb.io/v1beta1",
			"kind":       "L2Advertisement",
			"metadata": map[string]any{
				"name":      l2AdvertisementName,
				"namespace": kubeSystemNameSpace,
			},
			"spec": map[string]any{
				"ipAddressPools": ipAddrPools,
			},
		},
	}

	var l2Advertisement *unstructured.Unstructured
	var err error

	f := func() error {
		var retErr error
		var creationErr error
		l2Advertisement, creationErr = dc.Resource(l2AdvertisementGVR).Namespace(kubeSystemNameSpace).Create(ctx, obj, metav1.CreateOptions{})
		if creationErr != nil {
			retErr = fmt.Errorf("error creating unstructured l2Advertisement: %v", creationErr)
			klog.Error(retErr)
			return retErr
		}
		return nil
	}

	if err = backoff.Retry(f, backoff.WithMaxRetries(backoff.NewConstantBackOff(defaultConstantBackOffTime), maxRetries)); err != nil {
		klog.Errorf("err creating l2Advertisement after %q retries: %v", maxRetries, err)
		return nil, err
	}

	klog.Infof("l2Advertisement %s/%s created successfully", l2Advertisement.GetNamespace(), l2Advertisement.GetName())
	return l2Advertisement, err
}

func TestLoadBalancerService(ctx context.Context, cl k8sclient.Client, serviceName, testNamespace string, servicePort int32) error {
	err := WaitForServiceReadiness(ctx, cl, serviceName, testNamespace, corev1.ServiceTypeLoadBalancer)
	if err != nil {
		return err
	}
	service := corev1.Service{}
	err = cl.Get(ctx, k8sclient.ObjectKey{Name: serviceName, Namespace: testNamespace}, &service)
	if err != nil {
		return err
	}
	for _, ingress := range service.Status.LoadBalancer.Ingress {
		err := RunCurlFromBootstrapper(ctx, cl, ingress.IP, servicePort)
		if err != nil {
			return err
		}
	}
	return nil
}
