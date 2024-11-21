package ciliumconfig

import (
	"context"
	"errors"
	"testing"

	"github.com/cilium/cilium/pkg/gke/features"
	"github.com/cilium/cilium/pkg/k8s/client"
	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	k8sTesting "k8s.io/client-go/testing"
)

func TestGetCiliumConfig(t *testing.T) {
	ctx := context.Background()
	fakeclient, _ := client.NewFakeClientset()

	cmWithData := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      CiliumConfigMapName,
			Namespace: "kube-system",
		},
		Data: map[string]string{
			"labels": "k8s:key-a k8s:key-b",
		},
	}

	cmWithData2 := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      CiliumConfigMapName,
			Namespace: "kube-system",
		},
		Data: map[string]string{
			"labels": "k8s:key-a k8s:key-b",
			"test":   "default",
		},
	}

	cmNoData := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      CiliumConfigMapName,
			Namespace: "kube-system",
		},
	}

	cmOverrideWithData := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      GoogleOverrideConfigMapName,
			Namespace: "kube-system",
		},
		Data: map[string]string{
			"labels": "k8s:key-c",
		},
	}

	cmOverrideWithData2 := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      GoogleOverrideConfigMapName,
			Namespace: "kube-system",
		},
		Data: map[string]string{
			"labels": "k8s:key-c",
			"test":   "override",
		},
	}

	cmOverrideNoData := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      GoogleOverrideConfigMapName,
			Namespace: "kube-system",
		},
	}

	var ciliumConfigCM, ciliumConfigOverrideCM *corev1.ConfigMap

	fakeclient.KubernetesFakeClientset.PrependReactor("get", "*", func(action k8sTesting.Action) (handled bool, ret runtime.Object, err error) {
		pa := action.(k8sTesting.GetAction)
		if pa.GetName() == CiliumConfigMapName {
			if ciliumConfigCM == nil {
				return false, nil, errors.New("Not found")
			}
			return true, ciliumConfigCM, nil
		}
		if pa.GetName() == GoogleOverrideConfigMapName {
			if ciliumConfigOverrideCM == nil {
				return false, nil, errors.New("Not found")
			}
			return true, ciliumConfigOverrideCM, nil
		}
		return false, nil, nil
	})

	type testCase struct {
		name                   string
		ciliumConfigCM         *corev1.ConfigMap
		ciliumConfigOverrideCM *corev1.ConfigMap
		overrideEnabled        bool

		expectedData  map[string]string
		expectedError bool
	}

	tcs := []testCase{
		{
			name:                   "empty_configs",
			ciliumConfigCM:         nil,
			ciliumConfigOverrideCM: nil,
			expectedData:           nil,
			expectedError:          true,
		},
		{
			name:                   "only_cilium_config",
			ciliumConfigCM:         cmWithData,
			ciliumConfigOverrideCM: nil,
			expectedData: map[string]string{
				"labels": "k8s:key-a k8s:key-b",
			},
		},
		{
			name:                   "both_configs_override_off",
			ciliumConfigCM:         cmWithData,
			ciliumConfigOverrideCM: cmOverrideWithData,
			expectedData: map[string]string{
				"labels": "k8s:key-a k8s:key-b",
			},
		},
		{
			name:                   "both_configs_override_on",
			ciliumConfigCM:         cmWithData,
			ciliumConfigOverrideCM: cmOverrideWithData,
			expectedData: map[string]string{
				"labels": "k8s:key-c",
			},
			overrideEnabled: true,
		},
		{
			name:                   "override_no_data",
			ciliumConfigCM:         cmWithData,
			ciliumConfigOverrideCM: cmOverrideNoData,
			expectedData: map[string]string{
				"labels": "k8s:key-a k8s:key-b",
			},
			overrideEnabled: true,
		},
		{
			name:                   "one_field_override",
			ciliumConfigCM:         cmWithData2,
			ciliumConfigOverrideCM: cmOverrideWithData,
			expectedData: map[string]string{
				"labels": "k8s:key-c",
				"test":   "default",
			},
			overrideEnabled: true,
		},
		{
			name:                   "two_fields_override",
			ciliumConfigCM:         cmWithData2,
			ciliumConfigOverrideCM: cmOverrideWithData2,
			expectedData: map[string]string{
				"labels": "k8s:key-c",
				"test":   "override",
			},
			overrideEnabled: true,
		},
		{
			name:                   "both_no_data",
			ciliumConfigCM:         cmNoData,
			ciliumConfigOverrideCM: cmOverrideNoData,
			overrideEnabled:        true,
		},
		{
			name:                   "cilium_config_nil",
			ciliumConfigCM:         nil,
			ciliumConfigOverrideCM: cmOverrideWithData,
			overrideEnabled:        true,
			expectedError:          true,
		},
	}

	for _, tc := range tcs {
		// Don't run in parallel because tests require to use global variables
		// (config) and variables defined outside the scope of the test run.
		t.Run(tc.name, func(t *testing.T) {
			features.GlobalConfig.EnableGoogleConfigOverride = tc.overrideEnabled

			ciliumConfigCM = tc.ciliumConfigCM
			ciliumConfigOverrideCM = tc.ciliumConfigOverrideCM
			cm, err := GetCiliumConfig(ctx, fakeclient)
			if tc.expectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.expectedData, cm.Data)
			}
		})
	}
}
