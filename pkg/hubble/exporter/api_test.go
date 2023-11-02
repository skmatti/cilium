// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package exporter

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/cilium/cilium/api/v1/flow"
)

func TestCompareFlowLogConfigs(t *testing.T) {
	now := time.Now()
	future := now.Add(time.Minute)

	cases := []struct {
		name          string
		currentConfig *flowLogConfig
		newConfig     *flowLogConfig
		expectEqual   bool
	}{
		{
			name:          "should equal for same path",
			currentConfig: &flowLogConfig{FilePath: "path"},
			newConfig:     &flowLogConfig{FilePath: "path"},
			expectEqual:   true,
		},
		{
			name:          "should not equal for different path",
			currentConfig: &flowLogConfig{FilePath: "path"},
			newConfig:     &flowLogConfig{FilePath: "other"},
			expectEqual:   false,
		},
		{
			name:          "should equal for same end date",
			currentConfig: &flowLogConfig{End: &now},
			newConfig:     &flowLogConfig{End: &now},
			expectEqual:   true,
		},
		{
			name:          "should not equal for different end date",
			currentConfig: &flowLogConfig{End: &now},
			newConfig:     &flowLogConfig{End: &future},
			expectEqual:   false,
		},
		{
			name:          "should equal for same fieldmask",
			currentConfig: &flowLogConfig{FieldMask: []string{"a", "b"}},
			newConfig:     &flowLogConfig{FieldMask: []string{"a", "b"}},
			expectEqual:   true,
		},
		{
			name:          "should equal for same fieldmask in different order",
			currentConfig: &flowLogConfig{FieldMask: []string{"a", "b"}},
			newConfig:     &flowLogConfig{FieldMask: []string{"b", "a"}},
			expectEqual:   true,
		},
		{
			name:          "should not equal for different fieldmask",
			currentConfig: &flowLogConfig{FieldMask: []string{"a", "b"}},
			newConfig:     &flowLogConfig{FieldMask: []string{"c", "b"}},
			expectEqual:   false,
		},
		{
			name: "should equal for same include filters in different order",
			currentConfig: &flowLogConfig{IncludeFilters: FlowFilters{
				{
					SourcePod: []string{"default/"},
					EventType: []*flow.EventTypeFilter{
						{Type: 1},
					},
				},
				{
					DestinationPod: []string{"frontend/nginx-975996d4c-7hhgt"},
				},
			}},
			newConfig: &flowLogConfig{IncludeFilters: FlowFilters{
				{
					DestinationPod: []string{"frontend/nginx-975996d4c-7hhgt"},
				},
				{
					EventType: []*flow.EventTypeFilter{
						{Type: 1},
					},
					SourcePod: []string{"default/"},
				},
			}},
			expectEqual: true,
		},
		{
			name: "should not equal for different include filters",
			currentConfig: &flowLogConfig{IncludeFilters: FlowFilters{
				{
					SourcePod: []string{"kube-system/"},
					EventType: []*flow.EventTypeFilter{
						{Type: 1},
					},
				},
				{
					DestinationPod: []string{"frontend/nginx-975996d4c-7hhgt"},
				},
			}},
			newConfig: &flowLogConfig{IncludeFilters: FlowFilters{
				{
					DestinationPod: []string{"frontend/nginx-975996d4c-7hhgt"},
				},
				{
					EventType: []*flow.EventTypeFilter{
						{Type: 1},
					},
					SourcePod: []string{"default/"},
				},
			}},
			expectEqual: false,
		},
		{
			name: "should equal for same exclude filters in different order",
			currentConfig: &flowLogConfig{ExcludeFilters: FlowFilters{
				{
					SourcePod: []string{"default/"},
					EventType: []*flow.EventTypeFilter{
						{Type: 1},
					},
				},
				{
					DestinationPod: []string{"frontend/nginx-975996d4c-7hhgt"},
				},
			}},
			newConfig: &flowLogConfig{ExcludeFilters: FlowFilters{
				{
					DestinationPod: []string{"frontend/nginx-975996d4c-7hhgt"},
				},
				{
					EventType: []*flow.EventTypeFilter{
						{Type: 1},
					},
					SourcePod: []string{"default/"},
				},
			}},
			expectEqual: true,
		},
		{
			name: "should not equal for different exclude filters",
			currentConfig: &flowLogConfig{ExcludeFilters: FlowFilters{
				{
					SourcePod: []string{"kube-system/"},
					EventType: []*flow.EventTypeFilter{
						{Type: 1},
					},
				},
				{
					DestinationPod: []string{"frontend/nginx-975996d4c-7hhgt"},
				},
			}},
			newConfig: &flowLogConfig{ExcludeFilters: FlowFilters{
				{
					DestinationPod: []string{"frontend/nginx-975996d4c-7hhgt"},
				},
				{
					EventType: []*flow.EventTypeFilter{
						{Type: 1},
					},
					SourcePod: []string{"default/"},
				},
			}},
			expectEqual: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result := tc.currentConfig.equals(tc.newConfig)
			assert.Equal(t, tc.expectEqual, result)
		})
	}
}
