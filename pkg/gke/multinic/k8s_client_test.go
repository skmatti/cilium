//go:build !privileged_tests
// +build !privileged_tests

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
	"testing"

	multinicv1alpha1 "github.com/cilium/cilium/pkg/gke/apis/multinic/v1alpha1"
	multinicfakes "github.com/cilium/cilium/pkg/gke/client/multinic/clientset/versioned/fake"
	fakenetworkingv1alpha1 "github.com/cilium/cilium/pkg/gke/client/multinic/clientset/versioned/typed/multinic/v1alpha1/fake"
	multinicinformers "github.com/cilium/cilium/pkg/gke/client/multinic/informers/externalversions"
	"github.com/google/go-cmp/cmp"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clienttesting "k8s.io/client-go/testing"
)

func TestGetNetworkInterface(t *testing.T) {
	testNamespace := "test-namespace"
	interfaceName := "my-interface"
	testcases := []struct {
		desc          string
		existsInStore bool
	}{
		{
			desc:          "NetworkInterface exists",
			existsInStore: true,
		},
		{
			desc:          "NetworkInterface does not exist",
			existsInStore: false,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.desc, func(t *testing.T) {
			k8sClient := newK8sClient()
			interfaceLister := k8sClient.informerFactory.Networking().V1alpha1().NetworkInterfaces().Informer().GetIndexer()

			interfaceCR := &multinicv1alpha1.NetworkInterface{
				ObjectMeta: metav1.ObjectMeta{
					Name:      interfaceName,
					Namespace: testNamespace,
				},
			}
			var want *multinicv1alpha1.NetworkInterface
			if tc.existsInStore {
				want = interfaceCR
				err := interfaceLister.Add(interfaceCR)
				if err != nil {
					t.Fatalf("failed to add interface cr to interface lister : %s", err)
				}
			}

			got, err := k8sClient.GetNetworkInterface(interfaceName, testNamespace)
			if tc.existsInStore && err != nil {
				t.Fatalf("GetNetworkInterface returned an unexpected error: %s", err)
			}
			if !tc.existsInStore && err == nil {
				t.Fatalf("GetNetworkInterface should return an error but got nil")
			}

			if diff := cmp.Diff(got, want); diff != "" {
				t.Fatalf("Got diff for NetworkInterface (-got +want):\n%s", diff)
			}
		})
	}
}

func TestGetNetwork(t *testing.T) {
	networkName := "my-network"
	testcases := []struct {
		desc          string
		existsInStore bool
	}{
		{
			desc:          "Network exists",
			existsInStore: true,
		},
		{
			desc:          "Network does not exist",
			existsInStore: false,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.desc, func(t *testing.T) {
			k8sClient := newK8sClient()
			networkLister := k8sClient.informerFactory.Networking().V1alpha1().Networks().Informer().GetIndexer()

			networkCR := &multinicv1alpha1.Network{
				ObjectMeta: metav1.ObjectMeta{
					Name: networkName,
				},
			}
			var want *multinicv1alpha1.Network
			if tc.existsInStore {
				want = networkCR
				err := networkLister.Add(networkCR)
				if err != nil {
					t.Fatalf("failed to add interface cr to interface lister : %s", err)
				}
			}

			got, err := k8sClient.GetNetwork(networkName)
			if tc.existsInStore && err != nil {
				t.Fatalf("GetNetwork returned an unexpected error: %s", err)
			}
			if !tc.existsInStore && err == nil {
				t.Fatalf("GetNetwork should return an error but got nil")
			}

			if diff := cmp.Diff(got, want); diff != "" {
				t.Fatalf("Got diff for Network (-got +want):\n%s", diff)
			}
		})
	}
}

func TestUpdateNetworkInterfaceStatus(t *testing.T) {
	interfaceName := "my-interface"
	testNamespace := "test-namespace"
	networkName := "my-network"
	testInterface := multinicv1alpha1.NetworkInterface{
		ObjectMeta: metav1.ObjectMeta{
			Name:            interfaceName,
			Namespace:       testNamespace,
			ResourceVersion: "rv",
		},
		Spec: multinicv1alpha1.NetworkInterfaceSpec{
			NetworkName: networkName,
		},
	}

	testcases := []struct {
		desc          string
		oldStatus     multinicv1alpha1.NetworkInterfaceStatus
		updatedStatus multinicv1alpha1.NetworkInterfaceStatus
		updateError   error
	}{
		{
			desc: "update status",
			oldStatus: multinicv1alpha1.NetworkInterfaceStatus{
				IpAddresses: []string{"1.1.1.1"},
				MacAddress:  "aa:aa:aa:aa",
			},
			updatedStatus: multinicv1alpha1.NetworkInterfaceStatus{
				IpAddresses: []string{"2.2.2.2"},
				MacAddress:  "bb:bb:bb:bb",
			},
		},
		{
			desc:        "update status error",
			updateError: fmt.Errorf("update status error"),
		},
	}

	for _, tc := range testcases {
		t.Run(tc.desc, func(t *testing.T) {
			k8sClient := newK8sClient()

			oldInterface := testInterface.DeepCopy()
			oldInterface.Status = tc.oldStatus
			update := testInterface.DeepCopy()
			update.Status = tc.updatedStatus

			want := update.DeepCopy()
			if tc.updateError != nil {
				want = nil
				fakeClient := k8sClient.multinicClient.NetworkingV1alpha1().(*fakenetworkingv1alpha1.FakeNetworkingV1alpha1)
				fakeClient.PrependReactor("update", "networkinterfaces",
					func(action clienttesting.Action) (handled bool, ret runtime.Object, err error) {
						return true, nil, tc.updateError
					})
			}
			_, err := k8sClient.multinicClient.NetworkingV1alpha1().NetworkInterfaces(testNamespace).Create(context.TODO(), oldInterface, metav1.CreateOptions{})
			if err != nil {
				t.Fatalf("errored creating network interface: %s", err)
			}

			got, err := k8sClient.UpdateNetworkInterfaceStatus(context.TODO(), update)
			if tc.updateError == nil && err != nil {
				t.Fatalf("UpdateNetworkInterfaceStatus returned an unexpected error: %s", err)
			}
			if err == nil {
				if tc.updateError != nil {
					t.Fatalf("UpdateNetworkInterfaceStatus should return an error but got nil")
				}
				if diff := cmp.Diff(got, want); diff != "" {
					t.Fatalf("Got diff for returned NetworkInterface (-got +want):\n%s", diff)
				}
				queried, err := k8sClient.multinicClient.NetworkingV1alpha1().NetworkInterfaces(testNamespace).Get(context.TODO(), interfaceName, metav1.GetOptions{})
				if err != nil {
					t.Fatalf("errored querying for network interface from client: %s", err)
				}

				if diff := cmp.Diff(queried, want); diff != "" {
					t.Fatalf("Got diff for queried NetworkInterface (-got +want):\n%s", diff)
				}
			}
		})
	}
}

// newK8sClient returns an instance of the k8sClient and initializes the listers
func newK8sClient() *k8sClientImpl {
	multinicClient := multinicfakes.NewSimpleClientset()
	informerFactory := multinicinformers.NewSharedInformerFactory(multinicClient, 0)

	return &k8sClientImpl{
		multinicClient:  multinicClient,
		networkLister:   informerFactory.Networking().V1alpha1().Networks().Lister(),
		interfaceLister: informerFactory.Networking().V1alpha1().NetworkInterfaces().Lister(),
		informerFactory: informerFactory,
	}
}
