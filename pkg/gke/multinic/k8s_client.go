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
	"fmt"

	multinicv1alpha1 "github.com/cilium/cilium/pkg/gke/apis/multinic/v1alpha1"
	multinicclient "github.com/cilium/cilium/pkg/gke/client/multinic/clientset/versioned"
	multinicinformers "github.com/cilium/cilium/pkg/gke/client/multinic/informers/externalversions"
	multiniclisters "github.com/cilium/cilium/pkg/gke/client/multinic/listers/multinic/v1alpha1"
	"github.com/cilium/cilium/pkg/k8s"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
)

// K8sClient interface contains the methods that can be used to interact with the Network and
// NetworkInterface CRs.
type K8sClient interface {
	// GetNetworkInterface returns the specified NetworkInterface CR
	GetNetworkInterface(name, namespace string) (*multinicv1alpha1.NetworkInterface, error)

	// GetNetworkInterface returns the specified Network CR
	GetNetwork(name string) (*multinicv1alpha1.Network, error)

	// UpdateNetworkInterfaceStatus updates the NetworkInterface status with the provided status.
	UpdateNetworkInterfaceStatus(ctx context.Context, update *multinicv1alpha1.NetworkInterface) (*multinicv1alpha1.NetworkInterface, error)
}

// k8sClient is an implementation of the K8sClient interface
type k8sClientImpl struct {
	multinicClient  multinicclient.Interface
	networkLister   multiniclisters.NetworkLister
	interfaceLister multiniclisters.NetworkInterfaceLister
	informerFactory multinicinformers.SharedInformerFactory
}

// NewClient creates a new K8sClient and blocks for the underlying cache to sync before
// returning
func NewK8sClient() (K8sClient, error) {
	kubeConfig, err := k8s.CreateConfig()
	if err != nil {
		return &k8sClientImpl{}, fmt.Errorf("failed to create kube rest config: %w", err)
	}
	multinicClient, err := multinicclient.NewForConfig(kubeConfig)
	if err != nil {
		return &k8sClientImpl{}, fmt.Errorf("failed to create multinic client: %w", err)
	}
	informerFactory := multinicinformers.NewSharedInformerFactory(multinicClient, 0)
	k8sClient := &k8sClientImpl{
		multinicClient:  multinicClient,
		networkLister:   informerFactory.Networking().V1alpha1().Networks().Lister(),
		interfaceLister: informerFactory.Networking().V1alpha1().NetworkInterfaces().Lister(),
		informerFactory: informerFactory,
	}

	// The multinic K8s client only needs the listers but the informer go routines
	// need to be running for the cache to be populated. Informers are created when
	// listers are created.
	informerFactory.Start(wait.NeverStop)
	informerFactory.WaitForCacheSync(wait.NeverStop)

	return k8sClient, nil
}

// GetNetworkInterface returns the specified NetworkInterface. If the NetworkInterface is
// not in the store, it queries the api server.
func (c *k8sClientImpl) GetNetworkInterface(name, namespace string) (*multinicv1alpha1.NetworkInterface, error) {
	return c.interfaceLister.NetworkInterfaces(namespace).Get(name)
}

// GetNetwork returns the specified Network. If the Network is not in the store, it
// queries the api server.
func (c *k8sClientImpl) GetNetwork(name string) (*multinicv1alpha1.Network, error) {
	return c.networkLister.Get(name)
}

// UpdateNetworkInterfaceStatus updates the specified NetworkInterface's status with the provided status
func (c *k8sClientImpl) UpdateNetworkInterfaceStatus(ctx context.Context, update *multinicv1alpha1.NetworkInterface) (*multinicv1alpha1.NetworkInterface, error) {
	return c.multinicClient.NetworkingV1alpha1().NetworkInterfaces(update.Namespace).UpdateStatus(ctx, update, metav1.UpdateOptions{})
}
