package servicesteering

import (
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/metrics/metric"
)

const (
	namespace = metrics.CiliumAgentNamespace
	subsystem = "google_service_steering"

	labelReconcileType      = "reconcile_type"
	reconcileTypeController = "controller"
	reconcileTypeTrigger    = "trigger"

	labelOutcome             = metrics.LabelOutcome
	labelValueOutcomeSuccess = metrics.LabelValueOutcomeSuccess
	labelValueOutcomeFail    = metrics.LabelValueOutcomeFail
)

type sfcMetrics struct {
	Endpoints      metric.Gauge
	ReconcileTotal metric.Vec[metric.Counter]
}

func newMetrics() sfcMetrics {
	return sfcMetrics{
		Endpoints: metric.NewGauge(metric.GaugeOpts{
			ConfigName: namespace + "_" + subsystem + "endpoints_total",
			Namespace:  namespace,
			Subsystem:  subsystem,
			Name:       "endpoints_total",
			Help:       "Number of endpoints selected by a traffic selector.",
		}),
		ReconcileTotal: metric.NewCounterVec(metric.CounterOpts{
			ConfigName: namespace + "_" + subsystem + "reconcile_total",
			Namespace:  namespace,
			Subsystem:  subsystem,
			Name:       "reconcile_total",
			Help:       "Number of reconciliations per type.",
		}, []string{
			labelReconcileType,
			labelOutcome,
		}),
	}
}
