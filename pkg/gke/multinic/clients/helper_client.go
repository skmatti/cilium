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

package clients

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"

	networkv1 "github.com/GoogleCloudPlatform/gke-networking-api/apis/network/v1"
	nwversioned "github.com/GoogleCloudPlatform/gke-networking-api/client/network/clientset/versioned"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slimv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/node"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	v1 "k8s.io/client-go/applyconfigurations/core/v1"

	anutils "gke-internal.googlesource.com/anthos-networking/apis/v2/utils"
	ipamversioned "gke-internal.googlesource.com/anthos-networking/ipam-controller/api/client/clientset/versioned"
	ipamv1alpha1 "gke-internal.googlesource.com/anthos-networking/ipam-controller/api/v1alpha1"
)

// MultiNetworkHelperClient interface defines the methods useful for multinetwork resources handling.
type MultiNetworkHelperClient interface {
	// GetNetworkInterface returns the specified NetworkInterface CR
	GetNetworkInterface(ctx context.Context, name, namespace string) (*networkv1.NetworkInterface, error)

	// GetNetworkInterface returns the specified Network CR
	GetNetwork(ctx context.Context, name string) (*networkv1.Network, error)

	// PatchNetworkInterfaceStatus updates the NetworkInterface status with the provided status.
	PatchNetworkInterfaceStatus(ctx context.Context, obj *networkv1.NetworkInterface) error

	// PatchNetworkInterfaceAnnotations updates the NetworkInterface annotations.
	PatchNetworkInterfaceAnnotations(ctx context.Context, obj *networkv1.NetworkInterface) error

	// PatchPodAnnotation updates the pod annotation.
	PatchPodAnnotation(ctx context.Context, obj *slimv1.Pod, anno map[string]string) error

	// GetGKENetworkParamSet returns the specified GKENetworkParamSet pointed by the params ref inside the Network object.
	GetGKENetworkParamSet(ctx context.Context, ref *networkv1.NetworkParametersReference) (*networkv1.GKENetworkParamSet, error)

	// GetClusterCIDRConfigForNetwork fetches the clusterCIDRCofig based on the Network.
	GetClusterCIDRConfigForNetwork(ctx context.Context, nwName string) (*ipamv1alpha1.ClusterCIDRConfig, error)

	// Get Devices attached to networks
	GetNetworkDevices(ctx context.Context) ([]string, error)
}

// MultiNetworkHelperClientImpl is an implementation of the MultiNetworkHelperClient interface
type MultiNetworkHelperClientImpl struct {
	// Clientset to update k8s core API resources
	Clientset k8sClient.Clientset
	// NWClient to update GKE networking group resources
	NWClient nwversioned.Interface
	// IPAMClient to get ang/ipam-controller clusterCIDRConfig resources.
	IPAMClient ipamversioned.Interface
	// Handle for network resources
	Networks resource.Resource[*networkv1.Network]
	// Handle for GKENetworkParamSet resources
	GKENetworkParamSets resource.Resource[*networkv1.GKENetworkParamSet]
	// Handle for network interface resources
	NetworkInterfaces resource.Resource[*networkv1.NetworkInterface]
	// Handle for clusterCIDRConfig resources
	ClusterCIDRConfigs resource.Resource[*ipamv1alpha1.ClusterCIDRConfig]
}

func (c *MultiNetworkHelperClientImpl) GetNetworkInterface(ctx context.Context, name, namespace string) (*networkv1.NetworkInterface, error) {
	nwInfStore, err := c.NetworkInterfaces.Store(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch network interfaces store: %v", err)
	}
	networkInfs, exists, err := nwInfStore.GetByKey(resource.Key{Name: name, Namespace: namespace})
	if err != nil {
		return nil, fmt.Errorf("failed to fetch network interface %s/%s: from store %v", namespace, name, err)
	}
	if !exists {
		return nil, fmt.Errorf("network interface %s not found: %v", name, err)
	}
	return networkInfs, nil
}

// GetClusterCIDRConfigForNetwork filters ClusterCIDRConfig based on the network.
func (c *MultiNetworkHelperClientImpl) GetClusterCIDRConfigForNetwork(ctx context.Context, nwName string) (*ipamv1alpha1.ClusterCIDRConfig, error) {
	clusterCIDRConfigstore, err := c.ClusterCIDRConfigs.Store(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch clusterCIDRConfig store: %v", err)
	}

	for _, clusterCIDRConfig := range clusterCIDRConfigstore.List() {
		networkValue := *clusterCIDRConfig.Spec.Network
		if networkValue == nwName {
			return clusterCIDRConfig, nil
		}
	}
	return nil, fmt.Errorf("No ClusterCIDRConfig found for this Network %v", nwName)
}

func (c *MultiNetworkHelperClientImpl) GetNetwork(ctx context.Context, name string) (*networkv1.Network, error) {
	nwStore, err := c.Networks.Store(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch networks store: %v", err)
	}
	network, exists, err := nwStore.GetByKey(resource.Key{Name: name})
	if err != nil {
		return nil, fmt.Errorf("failed to fetch network %s: from store %v", name, err)
	}
	if !exists {
		return nil, fmt.Errorf("network %s not found: %v", name, err)
	}
	return network, nil
}

func (c *MultiNetworkHelperClientImpl) PatchNetworkInterfaceStatus(ctx context.Context, obj *networkv1.NetworkInterface) error {
	_, err := c.NWClient.NetworkingV1().NetworkInterfaces(obj.Namespace).UpdateStatus(ctx, obj, metav1.UpdateOptions{})
	return err
}

func (c *MultiNetworkHelperClientImpl) PatchNetworkInterfaceAnnotations(ctx context.Context, obj *networkv1.NetworkInterface) error {
	intf, err := c.GetNetworkInterface(ctx, obj.Name, obj.Namespace)
	if err != nil {
		return err
	}
	if reflect.DeepEqual(intf.Annotations, obj.Annotations) {
		return nil
	}
	raw, err := json.Marshal(obj.Annotations)
	if err != nil {
		return fmt.Errorf("failed to marshal network interface annotations: %v", err)
	}
	patch := fmt.Sprintf(`{"metadata":{"annotations":%s}}`, raw)
	_, err = c.NWClient.NetworkingV1().NetworkInterfaces(obj.Namespace).Patch(ctx, intf.Name, types.MergePatchType, []byte(patch), metav1.PatchOptions{})
	return err
}

func (c *MultiNetworkHelperClientImpl) PatchPodAnnotation(ctx context.Context, obj *slimv1.Pod, anno map[string]string) error {
	_, err := c.Clientset.CoreV1().Pods(obj.Namespace).ApplyStatus(ctx, v1.Pod(obj.Name, obj.Namespace).WithAnnotations(anno),
		metav1.ApplyOptions{
			FieldManager: "anetd-multinetwork-helper",
		})
	return err
}

func (c *MultiNetworkHelperClientImpl) GetGKENetworkParamSet(ctx context.Context, ref *networkv1.NetworkParametersReference) (*networkv1.GKENetworkParamSet, error) {
	if ref.Group != networkv1.GroupName || !strings.EqualFold(ref.Kind, "gkenetworkparamset") {
		// Unsupported params ref kind
		return nil, fmt.Errorf("unknown paramRef kind: %s/%s", ref.Group, ref.Kind)
	}
	if c.GKENetworkParamSets == nil {
		return nil, fmt.Errorf("gkenetworkparamset store not initialized")
	}

	gnpStore, err := c.GKENetworkParamSets.Store(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch gkenetworkparamset store: %v", err)
	}
	ns := ""
	if ref.Namespace != nil {
		ns = *ref.Namespace
	}
	gnp, exists, err := gnpStore.GetByKey(resource.Key{Name: ref.Name, Namespace: ns})
	if err != nil {
		return nil, fmt.Errorf("failed to fetch gkenetworkparamset %s/%s: from store %v", *ref.Namespace, ref.Name, err)
	}
	if !exists {
		return nil, fmt.Errorf("gkenetworkparamset %s/%s not found: %v", *ref.Namespace, ref.Name, err)
	}
	return gnp, nil
}

func refersToGNP(nw *networkv1.Network) bool {
	ref := nw.Spec.ParametersRef
	if ref == nil {
		return false
	}
	return ref.Group == networkv1.GroupName && strings.EqualFold(ref.Kind, "gkenetworkparamset")
}

func (c *MultiNetworkHelperClientImpl) GetNetworkDevices(ctx context.Context) ([]string, error) {
	devices := []string{}
	nwStore, err := c.Networks.Store(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get network store: %w", err)
	}
	networks := nwStore.List()
	for _, nw := range networks {
		// Skipping networks with paramset pointing to GKENetworkParamset.
		if refersToGNP(nw) {
			continue
		}
		ifName, _, err := anutils.InterfaceInfo(nw, node.GetAnnotations())
		if err != nil {
			continue
		}
		devices = append(devices, ifName)
	}
	return devices, nil
}
