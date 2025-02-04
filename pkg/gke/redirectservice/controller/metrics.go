package controller

import (
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/metrics/metric"
)

const (
	namespace = metrics.CiliumAgentNamespace
	subsystem = "google_redirect_service"

	labelRedirectPolicyName = "redirect_policy_name"
)

type RedirectServiceMetrics struct {
	RedirectBackendCount metric.Vec[metric.Gauge]
}

func NewMetrics() RedirectServiceMetrics {
	return RedirectServiceMetrics{
		RedirectBackendCount: metric.NewGaugeVec(metric.GaugeOpts{
			ConfigName: namespace + "_" + subsystem + "_" + "backend_count",
			Namespace:  namespace,
			Subsystem:  subsystem,
			Name:       "backend_count",
			Help:       "Number of redirect service backends",
		}, []string{
			labelRedirectPolicyName,
		}),
	}
}
