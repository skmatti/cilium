package endpointqueue

import (
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/metrics/metric"
)

const (
	namespace = metrics.CiliumAgentNamespace
	subsystem = "google_create_queue"

	labelReconcileType      = "reconcile_type"
	reconcileTypeStartup    = "startup"
	reconcileTypeFileNotify = "fsnotify"

	labelOutcome             = metrics.LabelOutcome
	labelValueOutcomeSuccess = metrics.LabelValueOutcomeSuccess
	labelValueOutcomeFail    = metrics.LabelValueOutcomeFail
)

type createQueueMetrics struct {
	ReconcileTotal metric.Vec[metric.Counter]
}

func newMetrics() createQueueMetrics {
	return createQueueMetrics{
		ReconcileTotal: metric.NewCounterVec(metric.CounterOpts{
			ConfigName: namespace + "_" + subsystem + "_" + "reconcile_total",
			Namespace:  namespace,
			Subsystem:  subsystem,
			Name:       "reconcile_total",
			Help:       "Number of create queue endpoint reconciliations",
		}, []string{
			labelReconcileType,
			labelOutcome,
		}),
	}
}
