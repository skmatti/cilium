// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package utils

import (
	"testing"

	"github.com/google/go-cmp/cmp"

	k8sconst "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	"github.com/cilium/cilium/pkg/option"
)

func TestUpdateSanitizedPodLabels(t *testing.T) {
	// Backup and restore original EndpointSystemLabels
	originalLabels := option.Config.EndpointSystemLabels
	defer func() {
		option.Config.EndpointSystemLabels = originalLabels
	}()

	tests := []struct {
		name           string
		systemLabels   map[string]string
		initialLabels  map[string]string
		expectedLabels map[string]string
	}{
		{
			name: "System labels set, add label",
			systemLabels: map[string]string{
				"topology.kubernetes.io/zone": "us-west1-a",
			},
			initialLabels: map[string]string{
				"app": "test",
			},
			expectedLabels: map[string]string{
				"app":                         "test",
				"topology.kubernetes.io/zone": "us-west1-a",
			},
		},
		{
			name: "System labels set, overwrite existing label",
			systemLabels: map[string]string{
				"topology.kubernetes.io/zone": "us-west1-b",
			},
			initialLabels: map[string]string{
				"app":                         "test",
				"topology.kubernetes.io/zone": "old-zone",
			},
			expectedLabels: map[string]string{
				"app":                         "test",
				"topology.kubernetes.io/zone": "us-west1-b",
			},
		},
		{
			name:         "System labels empty, no change",
			systemLabels: map[string]string{},
			initialLabels: map[string]string{
				"app":                         "test",
				"topology.kubernetes.io/zone": "old-zone",
			},
			expectedLabels: map[string]string{
				"app":                         "test",
				"topology.kubernetes.io/zone": "old-zone",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			option.Config.EndpointSystemLabels = tt.systemLabels
			labels := make(map[string]string)
			for k, v := range tt.initialLabels {
				labels[k] = v
			}

			updateSystemLabels(labels)
			if diff := cmp.Diff(tt.expectedLabels, labels); diff != "" {
				t.Errorf("updateSystemLabels() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestStripPodSpecialLabels(t *testing.T) {
	// Backup and restore original EndpointSystemLabels
	originalLabels := option.Config.EndpointSystemLabels
	defer func() {
		option.Config.EndpointSystemLabels = originalLabels
	}()

	tests := []struct {
		name           string
		systemLabels   map[string]string
		initialLabels  map[string]string
		expectedLabels map[string]string
	}{
		{
			name:         "Strip PodNamespaceMetaLabels",
			systemLabels: map[string]string{},
			initialLabels: map[string]string{
				"app":                                    "test",
				k8sconst.PodNamespaceMetaLabels + ".foo": "bar",
			},
			expectedLabels: map[string]string{
				"app": "test",
			},
		},
		{
			name:         "Strip PodNamespaceLabel",
			systemLabels: map[string]string{},
			initialLabels: map[string]string{
				"app":                      "test",
				k8sconst.PodNamespaceLabel: "default",
			},
			expectedLabels: map[string]string{
				"app": "test",
			},
		},
		{
			name: "Strip System Labels",
			systemLabels: map[string]string{
				"topology.kubernetes.io/zone": "us-west1-a",
			},
			initialLabels: map[string]string{
				"app":                         "test",
				"topology.kubernetes.io/zone": "us-west1-a",
			},
			expectedLabels: map[string]string{
				"app": "test",
			},
		},
		{
			name:         "Strip Cilium Labels",
			systemLabels: map[string]string{},
			initialLabels: map[string]string{
				"app":                    "test",
				k8sconst.PolicyLabelName: "foo",
			},
			expectedLabels: map[string]string{
				"app": "test",
			},
		},
		{
			name: "Strip All Special Labels",
			systemLabels: map[string]string{
				"topology.kubernetes.io/zone": "us-west1-a",
			},
			initialLabels: map[string]string{
				"app":                                    "test",
				k8sconst.PodNamespaceMetaLabels + ".foo": "bar",
				k8sconst.PodNamespaceLabel:               "default",
				"topology.kubernetes.io/zone":            "us-west1-a",
				k8sconst.PolicyLabelName:                 "foo",
			},
			expectedLabels: map[string]string{
				"app": "test",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			option.Config.EndpointSystemLabels = tt.systemLabels
			got := StripPodSpecialLabels(tt.initialLabels)
			if diff := cmp.Diff(tt.expectedLabels, got); diff != "" {
				t.Errorf("StripPodSpecialLabels() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
