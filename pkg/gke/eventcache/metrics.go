package eventcache

import (
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/prometheus/client_golang/prometheus"
)

const (
	LabelSource   = "source"
	LabelResource = "resource"
	LabelEvent    = "event"
	Subsystem     = "google_1n_hybrid_cache"
)

var (
	resourceEventDelay = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: metrics.Namespace,
		Subsystem: Subsystem,
		Name:      "kubeapi_td_propagation_differences_seconds",
		Help:      "Latency of information between Kube API and Traffic Director xDS.",
		Buckets: append(prometheus.ExponentialBuckets(0.0625, 2, 8), // 0.0625s, 0.125s, ... 1 s, 2s, ... 8s
			prometheus.LinearBuckets(16, 16, 16)..., // 16s, 32s, 48s, ... 256s,
		),
	}, []string{
		LabelResource,
		LabelEvent,
	})

	resourceEventLost = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: metrics.Namespace,
		Subsystem: Subsystem,
		Name:      "kubeapi_or_td_lost_event_total",
		Help:      "Lost resource event received from Kube API or via xDS from Traffic Director because the matching event from the other source is missing.",
	}, []string{
		LabelSource,
		LabelResource,
		LabelEvent,
	})

	resourceEventSkipped = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: metrics.Namespace,
		Subsystem: Subsystem,
		Name:      "kubeapi_or_td_skipped_event_total",
		Help:      "Skipped resource event received from Kube API or via xDS from Traffic Director because it was overwritten before being matched with an event from the other source.",
	}, []string{
		LabelSource,
		LabelResource,
		LabelEvent,
	})
)

func (h *HybridCache) InitMetrics(registry *metrics.Registry) {
	collectors := []prometheus.Collector{
		resourceEventDelay,
		resourceEventLost,
		resourceEventSkipped,
	}
	registry.MustRegister(collectors...)
}

func MustRegister(collectors []prometheus.Collector) {
	panic("unimplemented")
}
