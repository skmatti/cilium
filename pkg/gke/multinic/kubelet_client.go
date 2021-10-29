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
	"net"
	"net/url"
	"os"

	slimv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"google.golang.org/grpc"
	podresourcesv1 "k8s.io/kubelet/pkg/apis/podresources/v1"
)

const (
	// unixProtocol is the network protocol of unix socket.
	unixProtocol               = "unix"
	defaultKubeletAPISocket    = "unix:/var/lib/kubelet/pod-resources/kubelet.sock"
	defaultPodResourcesMaxSize = 1024 * 1024 * 16 // 16 Mb
)

// KubeletClient is a grpc client to query pod resources through the kubelet api.
type KubeletClient struct {
	conn *grpc.ClientConn
}

// NewKubeletClient returns an instance of KubeletClient with default kubelet api socket.
func NewKubeletClient(ctx context.Context) (*KubeletClient, error) {
	return newKubeletClientWithSocket(ctx, defaultKubeletAPISocket)
}

func dialer(ctx context.Context, addr string) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, unixProtocol, addr)
}

// getAddressFromEndpoint returns the address parsed from the given endpoint.
func getAddressFromEndpoint(endpoint string) (string, error) {
	u, err := url.Parse(endpoint)
	if err != nil {
		return "", fmt.Errorf("failed to parse the given endpoint %q: %v", endpoint, err)
	}
	if u.Scheme != unixProtocol {
		return "", fmt.Errorf("%q proctol is not supported, please use unix socket endpoint", u.Scheme)
	}
	// Check the existence of the socket path
	if _, err := os.Stat(u.Path); err != nil {
		return "", fmt.Errorf("error looking up the socket path %q: %v", u.Path, err)
	}

	return u.Path, nil
}

// newKubeletClientWithSocket initializes and returns an instance of KubeletClient with the given socket.
func newKubeletClientWithSocket(ctx context.Context, socket string) (*KubeletClient, error) {
	addr, err := getAddressFromEndpoint(socket)
	if err != nil {
		return nil, fmt.Errorf("failed getting address for the socket %q: %v", socket, err)
	}

	conn, err := grpc.DialContext(ctx, addr, grpc.WithInsecure(), grpc.WithContextDialer(dialer), grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(defaultPodResourcesMaxSize)))
	if err != nil {
		return nil, fmt.Errorf("error dialing socket %s: %v", socket, err)
	}
	return &KubeletClient{
		conn: conn,
	}, nil
}

// GetPodResources parses the response of the pod resources grpc call and
// returns a map of pod resource to the device ids for the given pod name and namespace tuple.
// A map of "resource name" -> "list of device id" is returned. For example, "kubevirt.io/ens192": ["ens192Mvp100"].
func (kc *KubeletClient) GetPodResources(ctx context.Context, pod *slimv1.Pod) (map[string][]string, error) {
	if pod.Name == "" || pod.Namespace == "" {
		return nil, fmt.Errorf("pod name or namespace cannot be empty")
	}
	lister := podresourcesv1.NewPodResourcesListerClient(kc.conn)
	resp, err := lister.List(ctx, &podresourcesv1.ListPodResourcesRequest{})
	if err != nil {
		return nil, fmt.Errorf("error listing pod resources: %v", err)
	}

	resourceMap := make(map[string][]string)
	for _, pr := range resp.PodResources {
		if pr.Name == pod.Name && pr.Namespace == pod.Namespace {
			for _, cnt := range pr.Containers {
				for _, dev := range cnt.Devices {
					resourceMap[dev.ResourceName] = append(resourceMap[dev.ResourceName], dev.DeviceIds...)
				}
			}
		}
	}
	return resourceMap, nil
}
