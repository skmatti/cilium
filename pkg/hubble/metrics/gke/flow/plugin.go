package flow

import (
	"github.com/cilium/cilium/pkg/hubble/metrics/api"
)

type flowPlugin struct{}

func (p *flowPlugin) NewHandler() api.Handler {
	return &flowHandler{}
}

func (p *flowPlugin) HelpText() string {
	return `gke-flow - Generic flow metrics
Reports number of processed flow events

Metrics:
  pod_flow_ingress_flows_count - Total number of ingress flows processed
  pod_flow_egress_flows_count - Total number of egress flows processed

Options:` +
		api.ContextOptionsHelp
}

func init() {
	api.DefaultRegistry().Register("gke-flow", &flowPlugin{})
}
