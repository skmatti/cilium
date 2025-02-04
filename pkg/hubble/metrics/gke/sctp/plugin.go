// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package sctp

import (
	"github.com/cilium/cilium/pkg/hubble/metrics/api"
)

type sctpFlowPlugin struct{}

func (p *sctpFlowPlugin) NewHandler() api.Handler {
	return &sctpFlowHandler{}
}

func (p *sctpFlowPlugin) HelpText() string {
	return `sctp - SCTP metrics
Metrics related to the SCTP protocol

Metrics:
  hubble_sctp_flows_processed_total - Total number of SCTP flows processed, labeled by verdict (dropped or forwarded).

Options:` +
		api.ContextOptionsHelp
}

func init() {
	api.DefaultRegistry().Register("sctp", &sctpFlowPlugin{})
}
