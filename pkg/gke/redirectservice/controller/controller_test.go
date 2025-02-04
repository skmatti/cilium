/*
Copyright 2020 Google LLC

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

package controller

import (
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/pkg/gke/apis/redirectservice/v1alpha1"
	fakeRedirectService "github.com/cilium/cilium/pkg/gke/client/redirectservice/clientset/versioned/fake"
	"github.com/cilium/cilium/pkg/k8s"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slimcorev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slimFlake "github.com/cilium/cilium/pkg/k8s/slim/k8s/client/clientset/versioned/fake"
	"github.com/cilium/cilium/pkg/redirectpolicy"
	"github.com/cilium/cilium/pkg/testutils"
	"github.com/stretchr/testify/require"
	"k8s.io/client-go/kubernetes/fake"
)

func TestValidation(t *testing.T) {
	testutils.PrivilegedTest(t)

	for _, tc := range []struct {
		desc        string
		rs          *v1alpha1.RedirectService
		expectError bool
	}{
		{
			desc: "Disallowed obj name",
			rs: &v1alpha1.RedirectService{
				ObjectMeta: metav1.ObjectMeta{
					Name: "foo",
				},
				Spec: v1alpha1.RedirectServiceSpec{},
			},
			expectError: true,
		},
		{
			desc: "Unsupported redirect type",
			rs: &v1alpha1.RedirectService{
				ObjectMeta: metav1.ObjectMeta{
					Name: "default",
				},
				Spec: v1alpha1.RedirectServiceSpec{
					Redirect: v1alpha1.RedirectSpec{
						Type:     "foo",
						Provider: v1alpha1.KubeDNSServiceProviderType,
					},
				},
			},
			expectError: true,
		},
		{
			desc: "Unsupported redirect service provider",
			rs: &v1alpha1.RedirectService{
				ObjectMeta: metav1.ObjectMeta{
					Name: "default",
				},
				Spec: v1alpha1.RedirectServiceSpec{
					Redirect: v1alpha1.RedirectSpec{
						Type:     v1alpha1.NodeLocalDNSRedirectServiceType,
						Provider: "foo",
					},
				},
			},
			expectError: true,
		},
		{
			desc: "Nodelocaldns redirect",
			rs: &v1alpha1.RedirectService{
				ObjectMeta: metav1.ObjectMeta{
					Name: "default",
				},
				Spec: v1alpha1.RedirectServiceSpec{
					Redirect: v1alpha1.RedirectSpec{
						Type:     v1alpha1.NodeLocalDNSRedirectServiceType,
						Provider: v1alpha1.KubeDNSServiceProviderType,
					},
				},
			},
			expectError: false,
		},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			controller, err := NewController(fake.NewSimpleClientset(), slimFlake.NewSimpleClientset(), fakeRedirectService.NewSimpleClientset(), &fakeRedirectPolicyManager{}, nil, nil)
			if err != nil {
				t.Fatalf("Cannot instantiate redirect service controller")
			}

			_, err = controller.validateObj(tc.rs)
			if err != nil && !tc.expectError {
				t.Fatalf("Expected no error but got %v", err)
			}
			if err == nil && tc.expectError {
				t.Fatalf("Expected non-nil error but got no error")
			}
		})
	}
}

func TestMetrics(t *testing.T) {
	testutils.PrivilegedTest(t)

	nldLRPKey := k8s.ServiceID{
		Name:      "default",
		Namespace: "kube-system",
	}

	rs := &v1alpha1.RedirectService{
		ObjectMeta: metav1.ObjectMeta{
			Name:      nldLRPKey.Name,
			Namespace: nldLRPKey.Namespace,
		},
		Spec: v1alpha1.RedirectServiceSpec{
			Redirect: v1alpha1.RedirectSpec{
				Type:     v1alpha1.NodeLocalDNSRedirectServiceType,
				Provider: v1alpha1.KubeDNSServiceProviderType,
			},
		},
	}

	redirectPolicyMetrics := NewMetrics()
	controller, err := NewController(fake.NewSimpleClientset(), slimFlake.NewSimpleClientset(), fakeRedirectService.NewSimpleClientset(), &fakeRedirectPolicyManager{}, nil, &redirectPolicyMetrics)
	require.Empty(t, err)

	_, err = controller.validateObj(rs)
	require.Empty(t, err)

	backendCountMetric, err := redirectPolicyMetrics.RedirectBackendCount.GetMetricWithLabelValues(nldLRPKey.String())
	require.Empty(t, err)
	require.EqualValues(t, backendCountMetric.Get(), 0)

	// Add redirect policy and check backend count
	controller.updateHandler(rs)
	require.EqualValues(t, backendCountMetric.Get(), 1)
}

type fakeRedirectPolicyManager struct{}

func (f *fakeRedirectPolicyManager) AddRedirectPolicy(config redirectpolicy.LRPConfig) (bool, error) {
	return true, nil
}

func (f *fakeRedirectPolicyManager) DeleteRedirectPolicy(config redirectpolicy.LRPConfig) error {
	return nil
}

func (f *fakeRedirectPolicyManager) GetLocalPodsForPolicy(config *redirectpolicy.LRPConfig) ([]string, error) {
	return []string{}, nil
}

func (f *fakeRedirectPolicyManager) OnDeletePod(pod *slim_corev1.Pod) {}

func (f *fakeRedirectPolicyManager) RemoveExistingNLDBackends(lrpConfig *redirectpolicy.LRPConfig) {}

func (f *fakeRedirectPolicyManager) GetNodeLocalDNSLRPBackends(lrpConfig *redirectpolicy.LRPConfig) (bool, int) {
	return true, 1
}

func (f *fakeRedirectPolicyManager) GetNodeLocalDNSLRPForPod(pod *slimcorev1.Pod) *redirectpolicy.LRPConfig {
	return nil
}
