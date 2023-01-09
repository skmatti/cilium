//go:build !privileged_tests

package dataplanev2encryption

import (
	"testing"

	"github.com/cilium/cilium/pkg/gke/apis/dataplanev2encryption/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sruntime "k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestIsWireguard(t *testing.T) {
	scheme := k8sruntime.NewScheme()
	corev1.AddToScheme(scheme)
	v1alpha1.AddToScheme(scheme)

	tests := []struct {
		name      string
		k8sClient client.Client
		wgEnabled bool
		wantErr   bool
	}{
		{
			name: "No CR",
			k8sClient: fake.NewClientBuilder().WithScheme(scheme).WithObjects(
				&corev1.Namespace{
					ObjectMeta: v1.ObjectMeta{Name: v1.NamespaceDefault}}).Build(),
			wgEnabled: false,
			wantErr:   false,
		},
		{
			name: "Wireguard Disabled",
			k8sClient: fake.NewClientBuilder().WithScheme(scheme).WithObjects(
				&corev1.Namespace{
					ObjectMeta: v1.ObjectMeta{Name: v1.NamespaceDefault}},
				&v1alpha1.DataplaneV2Encryption{
					ObjectMeta: v1.ObjectMeta{Name: v1.NamespaceDefault}}).Build(),
			wgEnabled: false,
			wantErr:   false,
		},
		{
			name: "Wireguard Enabled",
			k8sClient: fake.NewClientBuilder().WithScheme(scheme).WithObjects(
				&corev1.Namespace{
					ObjectMeta: v1.ObjectMeta{Name: v1.NamespaceDefault}},
				&v1alpha1.DataplaneV2Encryption{
					ObjectMeta: v1.ObjectMeta{Name: v1.NamespaceDefault},
					Spec: v1alpha1.DataplaneV2EncryptionSpec{
						Type:    v1alpha1.WireguardDataplaneV2EncryptionType,
						Enabled: true,
					}}).Build(),
			wgEnabled: true,
			wantErr:   false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if w, err := IsWireguard(test.k8sClient); (err != nil) != test.wantErr {
				t.Errorf("&quot;%s&quot; error = %v, wantErr %v", test.name, err, test.wantErr)
			} else if w != test.wgEnabled {
				t.Errorf("Wireguard unexpectedly enabled/disabled. Want %v got %v", test.wgEnabled, w)
			}
		})
	}
}
