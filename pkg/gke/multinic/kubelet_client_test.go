// Copyright 2021 Authors of Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build !privileged_tests
// +build !privileged_tests

package multinic

import (
	"context"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	slimv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/google/go-cmp/cmp"
	"google.golang.org/grpc"
	podresourcesv1 "k8s.io/kubelet/pkg/apis/podresources/v1"
)

const (
	podName           = "test-pod-name"
	nonMatchPodName   = "non-match-pod-name"
	podNs             = "test-ns"
	podContainerName0 = "test-container-name0"
	podContainerName1 = "test-container-name1"
	resourceName0     = "test-resource0"
	resourceName1     = "test-resource1"
	deviceID0         = "100"
	deviceID1         = "200"
	deviceID2         = "300"
	deviceID3         = "400"
)

type fakeResourceServer struct {
	server *grpc.Server
	// svcError controls whether the grpc call needs to return error.
	svcError bool
}

func (f *fakeResourceServer) GetAllocatableResources(ctx context.Context, req *podresourcesv1.AllocatableResourcesRequest) (*podresourcesv1.AllocatableResourcesResponse, error) {
	return &podresourcesv1.AllocatableResourcesResponse{}, nil
}

func (f *fakeResourceServer) List(ctx context.Context, req *podresourcesv1.ListPodResourcesRequest) (*podresourcesv1.ListPodResourcesResponse, error) {
	if f.svcError {
		return nil, fmt.Errorf("ListPodResourcesRequest failed")
	}

	devs0 := []*podresourcesv1.ContainerDevices{
		{
			ResourceName: resourceName0,
			DeviceIds:    []string{deviceID0, deviceID1},
		},
		{
			ResourceName: resourceName1,
			DeviceIds:    []string{deviceID2},
		},
	}

	devs1 := []*podresourcesv1.ContainerDevices{
		{
			ResourceName: resourceName1,
			DeviceIds:    []string{deviceID3},
		},
	}

	resp := &podresourcesv1.ListPodResourcesResponse{
		PodResources: []*podresourcesv1.PodResources{
			{
				Name:      podName,
				Namespace: podNs,
				Containers: []*podresourcesv1.ContainerResources{
					{
						Name:    podContainerName0,
						Devices: devs0,
					},
					{
						Name:    podContainerName1,
						Devices: devs1,
					},
				},
			},
		},
	}
	return resp, nil
}

// setUpKubeletClient sets up the environment for testing KubeletClient.
// The function creates a local unix socket and listener to the socket.
func setUpKubeletClient() (string, string, *fakeResourceServer, error) {
	var socketDir, socket string
	socketDir, err := ioutil.TempDir("", "kubelet-resource-client")
	if err != nil {
		return "", "", nil, err
	}

	// Assemble the full path of the unix socket.
	path := filepath.Join(socketDir, "kubelet.sock")
	socket = unixProtocol + ":" + path

	lis, err := net.Listen(unixProtocol, path)
	if err != nil {
		return socketDir, "", nil, err
	}
	fakeServer := &fakeResourceServer{server: grpc.NewServer()}
	podresourcesv1.RegisterPodResourcesListerServer(fakeServer.server, fakeServer)
	go fakeServer.server.Serve(lis)
	return socketDir, socket, fakeServer, nil
}

func tearDown(path string, fakeServer *fakeResourceServer) error {
	if fakeServer != nil {
		fakeServer.server.Stop()
	}
	return os.RemoveAll(path)
}

func getFakePod(name, ns string) *slimv1.Pod {
	return &slimv1.Pod{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:      name,
			Namespace: ns,
		},
	}
}

func TestGetPodResources(t *testing.T) {
	socketDir, testKubeletSocket, fakeServer, err := setUpKubeletClient()
	if err != nil {
		t.Fatalf("setUpKubeletClient() failed: %v", err)
	}
	defer func() {
		if err := tearDown(socketDir, fakeServer); err != nil {
			t.Errorf("tearDown() failed: %v", err)
		}
	}()
	testcases := []struct {
		desc    string
		fakePod *slimv1.Pod
		want    map[string][]string
		wantErr string
		grpcErr bool
	}{
		{
			desc:    "find pod resources successfully",
			fakePod: getFakePod(podName, podNs),
			want: map[string][]string{
				resourceName0: {deviceID0, deviceID1},
				resourceName1: {deviceID2, deviceID3},
			},
		},
		{
			desc:    "no match pod resources",
			fakePod: getFakePod(nonMatchPodName, podNs),
			want:    map[string][]string{},
		},
		{
			desc:    "podresources list api error",
			fakePod: getFakePod(podName, podNs),
			grpcErr: true,
			wantErr: "error listing pod resources",
		},
		{
			desc:    "empty pod name or namespace",
			fakePod: getFakePod("", ""),
			wantErr: "pod name or namespace cannot be empty",
		},
	}
	for _, tc := range testcases {
		t.Run(tc.desc, func(t *testing.T) {
			fakeServer.svcError = tc.grpcErr
			kc, err := newKubeletClientWithSocket(context.Background(), testKubeletSocket)
			if err != nil {
				t.Fatalf("newKubeletClientWithSocket() failed: %v", err)
			}
			got, gotErr := kc.GetPodResources(context.Background(), tc.fakePod)
			if gotErr != nil {
				if tc.wantErr == "" {
					t.Fatalf("kc.GetPodResources() returns error %v but want nil", gotErr)
				}
				if !strings.Contains(gotErr.Error(), tc.wantErr) {
					t.Fatalf("kc.GetPodResources() returns error %v but want %v", gotErr, tc.wantErr)
				}
				return
			}

			if tc.wantErr != "" {
				t.Fatalf("kc.GetPodResources() returns nil but want error %v", tc.wantErr)
			}

			if diff := cmp.Diff(got, tc.want); diff != "" {
				t.Fatalf("kc.GetPodResources() returns unexpected output (-got, +want):\n%s", diff)
			}
		})
	}
}

func TestNewKubeletClientWithSocket(t *testing.T) {
	socketDir, testKubeletSocket, fakeServer, err := setUpKubeletClient()
	if err != nil {
		t.Fatalf("setUpKubeletClient() failed: %v", err)
	}
	defer func() {
		if err := tearDown(socketDir, fakeServer); err != nil {
			t.Errorf("tearDown() failed: %v", err)
		}
	}()
	testcases := []struct {
		desc    string
		socket  string
		wantErr string
	}{
		{
			desc:   "kubelet client initialized successfully",
			socket: testKubeletSocket,
		},
		{
			desc:    "unsupported protocol",
			socket:  "tcp:/path",
			wantErr: "proctol is not supported, please use unix socket endpoint",
		},
		{
			desc:    "url parse failure",
			socket:  ":",
			wantErr: "failed to parse the given endpoint",
		},
		{
			desc:    "non-exist endpoint socket",
			socket:  "unix:non-exist",
			wantErr: "error looking up the socket path",
		},
	}
	for _, tc := range testcases {
		t.Run(tc.desc, func(t *testing.T) {
			_, gotErr := newKubeletClientWithSocket(context.Background(), tc.socket)
			if gotErr != nil {
				if tc.wantErr == "" {
					t.Fatalf("newKubeletClientWithSocket(ctx, %s) returns error %v but want nil", tc.socket, gotErr)
				}
				if !strings.Contains(gotErr.Error(), tc.wantErr) {
					t.Fatalf("newKubeletClientWithSocket(ctx, %s) returns error %v but want %v", tc.socket, gotErr, tc.wantErr)
				}
				return
			}

			if tc.wantErr != "" {
				t.Fatalf("newKubeletClientWithSocket(ctx, %s) returns nil but want error %v", tc.socket, tc.wantErr)
			}
		})
	}
}
