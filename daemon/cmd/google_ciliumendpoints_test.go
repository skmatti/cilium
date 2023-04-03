// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !privileged_tests

package cmd

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	k8stesting "k8s.io/client-go/testing"
	"k8s.io/client-go/tools/cache"

	"github.com/cilium/cilium/pkg/endpoint"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/fake"
	slimmetav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/k8s/types"
	"github.com/cilium/cilium/pkg/k8s/watchers"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
)

func Test_cleanStaleCEPWhenMultiNIC(t *testing.T) {
	tests := map[string]struct {
		ciliumEndpoints []types.CiliumEndpoint
		// endpoints in endpointManaged.
		managedEndpoints map[string][]*endpoint.Endpoint
		// expectedDeletedSet contains CiliumEndpoints that are expected to be deleted
		// during test, in the form '<namespace>/<cilium_endpoint>'.
		expectedDeletedSet []string
	}{
		"Multi-NIC CEPs with local pods without endpoints should be GCd": {
			ciliumEndpoints:    []types.CiliumEndpoint{multinicCEP("foo-net1-1234", "x", node.GetCiliumEndpointNodeIP(), "foo"), multinicCEP("bar-net1-4321", "y", node.GetCiliumEndpointNodeIP(), "bar")},
			managedEndpoints:   map[string][]*endpoint.Endpoint{"y/bar": {&endpoint.Endpoint{}}},
			expectedDeletedSet: []string{"x/foo-net1-1234"},
		},
		"Non local Multi-NIC CEPs should not be GCd": {
			ciliumEndpoints:    []types.CiliumEndpoint{multinicCEP("foo-net1-1234", "x", "1.2.3.4", "foo")},
			managedEndpoints:   map[string][]*endpoint.Endpoint{},
			expectedDeletedSet: []string{},
		},
		"Nothing should be deleted if fields are missing": {
			ciliumEndpoints:    []types.CiliumEndpoint{multinicCEP("", "", "", "")},
			managedEndpoints:   map[string][]*endpoint.Endpoint{},
			expectedDeletedSet: []string{},
		},
	}
	option.Config.EnableGoogleMultiNIC = true
	defer func() {
		option.Config.EnableGoogleMultiNIC = false
	}()
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			assert := assert.New(t)
			d := Daemon{
				k8sWatcher: &watchers.K8sWatcher{},
			}

			fakeClient := fake.NewSimpleClientset()
			cepStore := cache.NewIndexer(cache.DeletionHandlingMetaNamespaceKeyFunc, cache.Indexers{
				"localNode": watchers.CreateCiliumEndpointLocalPodIndexFunc(),
			})

			for _, cep := range test.ciliumEndpoints {
				_, err := fakeClient.CiliumV2().CiliumEndpoints(cep.Namespace).Create(context.Background(), &ciliumv2.CiliumEndpoint{
					ObjectMeta: metav1.ObjectMeta{
						Name:      cep.Name,
						Namespace: cep.Namespace,
					},
				}, metav1.CreateOptions{})
				assert.NoError(err)
				cepStore.Add(cep.DeepCopy())
			}
			d.k8sWatcher.SetIndexer("ciliumendpoint", cepStore)
			l := &lock.Mutex{}
			var deletedSet []string
			fakeClient.PrependReactor("delete", "ciliumendpoints", k8stesting.ReactionFunc(func(action k8stesting.Action) (bool, runtime.Object, error) {
				l.Lock()
				defer l.Unlock()
				a := action.(k8stesting.DeleteAction)
				deletedSet = append(deletedSet, fmt.Sprintf("%s/%s", a.GetNamespace(), a.GetName()))
				return true, nil, nil
			}))

			epm := &fakeEPManager{epsByPodName: test.managedEndpoints}

			err := d.cleanStaleCEPs(context.Background(), epm, fakeClient.CiliumV2(), false)

			assert.NoError(err)
			assert.ElementsMatch(test.expectedDeletedSet, deletedSet)
		})
	}
}

func Test_cleanStaleCEPinCESWhenMultiNIC(t *testing.T) {
	tc := map[string]struct {
		ciliumEndpointSlice *v2alpha1.CiliumEndpointSlice
		// endpoints in endpointManager.
		managedEndpoints map[string][]*endpoint.Endpoint
		// expectedDeletedSet contains CiliumEndpoints that are expected to be deleted
		// during test, in the form '<namespace>/<cilium_endpoint>'.
		expectedDeletedSet []string
	}{
		"Multi-NIC CEPs with local pods with endpoints should not be GCd": {
			ciliumEndpointSlice: &v2alpha1.CiliumEndpointSlice{
				Endpoints: []v2alpha1.CoreCiliumEndpoint{multinicCoreCEP("foo-net1-1234", node.GetCiliumEndpointNodeIP(), "1.2.3.4", "")},
				Namespace: "x",
			},
			managedEndpoints:   map[string][]*endpoint.Endpoint{"y/bar": {&endpoint.Endpoint{IPv4: []byte("1.2.3.4"), ID: 1}}},
			expectedDeletedSet: []string{},
		},
		"Multi-NIC CEPs with local pods with IPv6 endpoints should not be GCd": {
			ciliumEndpointSlice: &v2alpha1.CiliumEndpointSlice{
				Endpoints: []v2alpha1.CoreCiliumEndpoint{multinicCoreCEP("foo-net1-1234", node.GetCiliumEndpointNodeIP(), "", "2002::1234:abcd:ffff:c0a8:101/64")},
				Namespace: "x",
			},
			managedEndpoints:   map[string][]*endpoint.Endpoint{"y/bar": {&endpoint.Endpoint{IPv6: []byte("2002::1234:abcd:ffff:c0a8:101/64"), ID: 1}}},
			expectedDeletedSet: []string{},
		},
		"Multi-NIC CEPs with local pods without endpoints should be GCd": {
			ciliumEndpointSlice: &v2alpha1.CiliumEndpointSlice{
				Endpoints: []v2alpha1.CoreCiliumEndpoint{multinicCoreCEP("foo-net1-1234", node.GetCiliumEndpointNodeIP(), "1.2.3.4", "")},
				Namespace: "x",
			},
			managedEndpoints:   map[string][]*endpoint.Endpoint{"y/bar": {&endpoint.Endpoint{IPv4: []byte("5.6.7.8"), ID: 1}}},
			expectedDeletedSet: []string{"x/foo-net1-1234"},
		},
		"Non local Multi-NIC CEPs should not be GCd": {
			ciliumEndpointSlice: &v2alpha1.CiliumEndpointSlice{
				Endpoints: []v2alpha1.CoreCiliumEndpoint{multinicCoreCEP("foo-net1-1234", "9.10.11.12", "1.2.3.4", "")},
				Namespace: "x",
			},
			managedEndpoints:   map[string][]*endpoint.Endpoint{"y/bar": {&endpoint.Endpoint{IPv4: []byte("5.6.7.8"), ID: 1}}},
			expectedDeletedSet: []string{},
		},
		"Nothing should be deleted if fields are missing": {
			ciliumEndpointSlice: &v2alpha1.CiliumEndpointSlice{
				Endpoints: []v2alpha1.CoreCiliumEndpoint{multinicCoreCEP("", "", "", "")},
				Namespace: "x",
			},
			managedEndpoints:   map[string][]*endpoint.Endpoint{"y/bar": {&endpoint.Endpoint{IPv4: []byte("5.6.7.8"), ID: 1}}},
			expectedDeletedSet: []string{},
		},
	}
	option.Config.EnableGoogleMultiNIC = true
	option.Config.EnableCiliumEndpointSlice = true
	defer func() {
		option.Config.EnableGoogleMultiNIC = false
		option.Config.EnableCiliumEndpointSlice = false
	}()
	for name, test := range tc {
		t.Run(name, func(t *testing.T) {
			assert := assert.New(t)
			// set up daemon with endpoint manager
			d := Daemon{
				k8sWatcher: &watchers.K8sWatcher{},
			}
			d.endpointManager = WithCustomEndpointManager(&watchers.EndpointSynchronizer{})
			for _, eps := range test.managedEndpoints {
				for _, ep := range eps {
					d.endpointManager.UpdateIDReferences(ep)
				}
			}
			// create cilium endpoint slice
			fakeClient := fake.NewSimpleClientset()
			cepStore := cache.NewIndexer(cache.DeletionHandlingMetaNamespaceKeyFunc, cache.Indexers{
				"localNode": watchers.CreateCiliumEndpointLocalPodIndexFunc(),
			})
			_, err := fakeClient.CiliumV2alpha1().CiliumEndpointSlices().Create(context.Background(), test.ciliumEndpointSlice, metav1.CreateOptions{})
			assert.NoError(err)
			for _, cep := range test.ciliumEndpointSlice.Endpoints {
				_, err := fakeClient.CiliumV2().CiliumEndpoints(test.ciliumEndpointSlice.Namespace).Create(context.Background(), &ciliumv2.CiliumEndpoint{
					ObjectMeta: metav1.ObjectMeta{
						Name:      cep.Name,
						Namespace: test.ciliumEndpointSlice.Namespace,
					},
					Status: ciliumv2.EndpointStatus{
						Networking: &ciliumv2.EndpointNetworking{
							NodeIP: cep.Networking.NodeIP,
						},
					},
				}, metav1.CreateOptions{})
				assert.NoError(err)
				cepStore.Add(cep.DeepCopy())
			}
			// add endpoints to the endpoint store
			for _, cep := range test.ciliumEndpointSlice.Endpoints {
				cepStore.Add(cep.DeepCopy())
			}
			d.k8sWatcher.SetIndexer("ciliumendpoint", cepStore)
			// prepare deleted endpoints set
			l := &lock.Mutex{}
			var deletedSet []string
			fakeClient.PrependReactor("delete", "ciliumendpoints", k8stesting.ReactionFunc(func(action k8stesting.Action) (bool, runtime.Object, error) {
				l.Lock()
				defer l.Unlock()
				a := action.(k8stesting.DeleteAction)
				deletedSet = append(deletedSet, fmt.Sprintf("%s/%s", a.GetNamespace(), a.GetName()))
				return true, nil, nil
			}))

			epm := &fakeEPManager{epsByPodName: test.managedEndpoints}
			err = d.cleanStaleCEPinCESWhenMultiNIC(context.Background(), epm, fakeClient.CiliumV2(), []interface{}{test.ciliumEndpointSlice})
			assert.NoError(err)
			assert.ElementsMatch(test.expectedDeletedSet, deletedSet)
		})
	}
}

func multinicCoreCEP(name, nodeIP, ipv4, ipv6 string) v2alpha1.CoreCiliumEndpoint {
	return v2alpha1.CoreCiliumEndpoint{
		Name: name,
		Networking: &ciliumv2.EndpointNetworking{
			NodeIP: nodeIP,
			Addressing: ciliumv2.AddressPairList{
				&ciliumv2.AddressPair{IPV4: ipv4, IPV6: ipv6},
			},
		},
	}
}

func multinicCEP(name, ns, nodeIP, podName string) types.CiliumEndpoint {
	return types.CiliumEndpoint{
		ObjectMeta: slimmetav1.ObjectMeta{
			Name: name,
			OwnerReferences: []slimmetav1.OwnerReference{
				{
					Kind: "Pod",
					Name: podName,
				},
			},
			Annotations: map[string]string{"networking.gke.io/multinic": "true"},
			Namespace:   ns,
		},
		Networking: &ciliumv2.EndpointNetworking{
			NodeIP: nodeIP,
		},
	}
}

func (epm *fakeEPManager) LookupEndpointsByPodName(name string) []*endpoint.Endpoint {
	eps, ok := epm.epsByPodName[name]
	if !ok {
		return nil
	}
	return eps
}
