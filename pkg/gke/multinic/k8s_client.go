/*
Copyright 2021 Google LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package multinic

import (
	"context"
	"encoding/json"
	"fmt"

	v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	networkv1 "gke-internal.googlesource.com/anthos-networking/apis/v2/network/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// K8sClient interface contains the methods that can be used to interact with the Network and
// NetworkInterface CRs.
type K8sClient interface {
	// GetNetworkInterface returns the specified NetworkInterface CR
	GetNetworkInterface(ctx context.Context, name, namespace string) (*networkv1.NetworkInterface, error)

	// GetNetworkInterface returns the specified Network CR
	GetNetwork(ctx context.Context, name string) (*networkv1.Network, error)

	// PatchNetworkInterfaceStatus updates the NetworkInterface status with the provided status.
	PatchNetworkInterfaceStatus(ctx context.Context, obj *networkv1.NetworkInterface) error

	// CreateNetworkInterface creates the network interface object
	CreateNetworkInterface(ctx context.Context, obj *networkv1.NetworkInterface) error

	// DeleteNetworkInterface deletes the network interface object
	DeleteNetworkInterface(ctx context.Context, obj *networkv1.NetworkInterface) error

	// SetPodIPsAnnotation sets the pod annotation for additional pod IPs assigned to the pod
	SetPodIPsAnnotation(ctx context.Context, pod *v1.Pod, podIPs *networkv1.PodIPsAnnotation) error
}

// k8sClientImpl is an implementation of the K8sClient interface
// It helps to restrict the usage of the underlying generic controller-runtime client.
type k8sClientImpl struct {
	client client.Client
}

// NewK8sClient creates a new K8sClient
func NewK8sClient(client client.Client) K8sClient {
	return &k8sClientImpl{
		client: client,
	}
}

func namespacedName(name, namespace string) types.NamespacedName {
	return types.NamespacedName{
		Name:      name,
		Namespace: namespace,
	}
}

func (c *k8sClientImpl) GetNetworkInterface(ctx context.Context, name, namespace string) (*networkv1.NetworkInterface, error) {
	intf := &networkv1.NetworkInterface{}
	if err := c.client.Get(ctx, namespacedName(name, namespace), intf); err != nil {
		return nil, err
	}
	return intf, nil
}

func (c *k8sClientImpl) GetNetwork(ctx context.Context, name string) (*networkv1.Network, error) {
	network := &networkv1.Network{}
	if err := c.client.Get(ctx, namespacedName(name, ""), network); err != nil {
		return nil, err
	}
	return network, nil
}

func (c *k8sClientImpl) PatchNetworkInterfaceStatus(ctx context.Context, obj *networkv1.NetworkInterface) error {
	intf := &networkv1.NetworkInterface{}
	if err := c.client.Get(ctx, namespacedName(obj.Name, obj.Namespace), intf); err != nil {
		return err
	}
	intfClean := intf.DeepCopy()
	intf.Status = *obj.Status.DeepCopy()
	intf.SetAnnotations(obj.Annotations)
	return c.client.Status().Patch(ctx, intf, client.MergeFrom(intfClean))
}

func (c *k8sClientImpl) CreateNetworkInterface(ctx context.Context, obj *networkv1.NetworkInterface) error {
	return c.client.Create(ctx, obj)
}

func (c *k8sClientImpl) DeleteNetworkInterface(ctx context.Context, obj *networkv1.NetworkInterface) error {
	return c.client.Delete(ctx, obj)
}

func (c *k8sClientImpl) SetPodIPsAnnotation(ctx context.Context, obj *v1.Pod, podIPs *networkv1.PodIPsAnnotation) error {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      obj.Name,
			Namespace: obj.Namespace,
		},
	}
	podIPsValue, err := json.Marshal(podIPs)
	if err != nil {
		return fmt.Errorf("failed to marshal pod IPs annotation %v: %v", podIPs, err)
	}
	raw, err := json.Marshal(map[string]string{
		networkv1.PodIPsAnnotationKey: string(podIPsValue),
	})
	if err != nil {
		return fmt.Errorf("failed to marshal pod annotations: %v", err)
	}
	patch := fmt.Sprintf(`{"metadata":{"annotations":%s}}`, raw)
	log.Infof("applying patch %s to pod %s", patch, pod.Name)
	return c.client.Status().Patch(ctx, pod, client.RawPatch(types.StrategicMergePatchType, []byte(patch)))
}
