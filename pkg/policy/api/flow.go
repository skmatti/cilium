// SPDX-License-Identifier: Apache-2.0

package api

import (
	"github.com/cilium/cilium/api/v1/flow"
)

func IsFlowAllowed(f *flow.Flow) bool {
	v := f.GetVerdict()
	return v == flow.Verdict_FORWARDED || v == flow.Verdict_REDIRECTED
}

func IsFlowEvent(f *flow.Flow, t int) bool {
	return f.GetEventType().GetType() == int32(t)
}
