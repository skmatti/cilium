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

	networkv1alpha1 "gke-internal.googlesource.com/anthos-networking/apis/network/v1alpha1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// K8sClient interface contains the methods that can be used to interact with the Network and
// NetworkInterface CRs.
type K8sClient interface {
	// GetNetworkInterface returns the specified NetworkInterface CR
	GetNetworkInterface(ctx context.Context, name, namespace string) (*networkv1alpha1.NetworkInterface, error)

	// GetNetworkInterface returns the specified Network CR
	GetNetwork(ctx context.Context, name string) (*networkv1alpha1.Network, error)

	// UpdateNetworkInterfaceStatus updates the NetworkInterface status with the provided status.
	UpdateNetworkInterfaceStatus(ctx context.Context, obj *networkv1alpha1.NetworkInterface) error
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

func (c *k8sClientImpl) GetNetworkInterface(ctx context.Context, name, namespace string) (*networkv1alpha1.NetworkInterface, error) {
	intf := &networkv1alpha1.NetworkInterface{}
	if err := c.client.Get(ctx, namespacedName(name, namespace), intf); err != nil {
		return nil, err
	}
	return intf, nil
}

func (c *k8sClientImpl) GetNetwork(ctx context.Context, name string) (*networkv1alpha1.Network, error) {
	network := &networkv1alpha1.Network{}
	if err := c.client.Get(ctx, namespacedName(name, ""), network); err != nil {
		return nil, err
	}
	return network, nil
}

func (c *k8sClientImpl) UpdateNetworkInterfaceStatus(ctx context.Context, obj *networkv1alpha1.NetworkInterface) error {
	return c.client.Status().Update(ctx, obj)
}
