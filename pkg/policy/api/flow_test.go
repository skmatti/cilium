// SPDX-License-Identifier: Apache-2.0

package api

import (
	"testing"

	"github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/pkg/monitor/api"
)

func TestIsFlowAllowed(t *testing.T) {
	tests := []struct {
		name string
		f    *flow.Flow
		want bool
	}{

		{
			name: "allow_forwarded",
			f: &flow.Flow{
				Verdict: flow.Verdict_FORWARDED,
			},
			want: true,
		},
		{
			name: "allow_redirected",
			f: &flow.Flow{
				Verdict: flow.Verdict_REDIRECTED,
			},
			want: true,
		},
		{
			name: "not_allowed_nil",
		},
		{
			name: "not_allowed_unspecified",
			f:    &flow.Flow{},
		},
		{
			name: "not_allowed_audit",
			f: &flow.Flow{
				Verdict: flow.Verdict_AUDIT,
			},
		},
		{
			name: "not_allowed_dropped",
			f: &flow.Flow{
				Verdict: flow.Verdict_DROPPED,
			},
		},
		{
			name: "not_allowed_error",
			f: &flow.Flow{
				Verdict: flow.Verdict_ERROR,
			},
		},
		{
			name: "not_allowed_traced",
			f: &flow.Flow{
				Verdict: flow.Verdict_TRACED,
			},
		},
		{
			name: "not_allowed_translated",
			f: &flow.Flow{
				Verdict: flow.Verdict_TRANSLATED,
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsFlowAllowed(tc.f); got != tc.want {
				t.Errorf("IsFlowAllowed() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestIsFlowEvent(t *testing.T) {
	tests := []struct {
		name string
		f    *flow.Flow
		t    int
		want bool
	}{
		{
			name: "nil_flow",
			t:    api.MessageTypeUnspec,
			want: true,
		},
		{
			name: "unspecified_flow_event",
			f:    &flow.Flow{},
			t:    api.MessageTypeUnspec,
			want: true,
		},
		{
			name: "policy_verdict_mismatch",
			f: &flow.Flow{
				EventType: &flow.CiliumEventType{
					Type: api.MessageTypePolicyVerdict,
				},
			},
			t: api.MessageTypeUnspec,
		},
		{
			name: "policy_verdict_match",
			f: &flow.Flow{
				EventType: &flow.CiliumEventType{
					Type: api.MessageTypePolicyVerdict,
				},
			},
			t:    api.MessageTypePolicyVerdict,
			want: true,
		},
		{
			name: "drop_mismatch",
			f: &flow.Flow{
				EventType: &flow.CiliumEventType{
					Type: api.MessageTypeDrop,
				},
			},
			t: api.MessageTypePolicyVerdict,
		},
		{
			name: "drop_match",
			f: &flow.Flow{
				EventType: &flow.CiliumEventType{
					Type: api.MessageTypeDrop,
				},
			},
			t:    api.MessageTypeDrop,
			want: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsFlowEvent(tc.f, tc.t); got != tc.want {
				t.Errorf("IsFlowEvent() = %v, want %v", got, tc.want)
			}
		})
	}
}
