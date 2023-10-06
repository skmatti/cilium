package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
)

const (
	subsystemMultiNetwork = "google_multinet"

	labelNetwork     = "network"
	labelNetworkType = "network_type"
)

var (
	MultiNetworkEndpoint    = NoOpGaugeVec
	MultiNetworkPodCreation = NoOpCounterVec
	MultiNetworkIpamEvent   = NoOpCounterVec
)

// TODO: Switch to Hive's cell.Metric in v1.14+
func googleMetrics() []prometheus.Collector {
	MultiNetworkEndpoint = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: Namespace,
		Subsystem: subsystemMultiNetwork,
		Name:      "endpoints_total",
		Help:      "Number of multi-network endpoints managed by this agent.",
	}, []string{
		labelNetwork,
		labelNetworkType,
	})
	MultiNetworkPodCreation = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: Namespace,
		Subsystem: subsystemMultiNetwork,
		Name:      "pod_creations_total",
		Help:      "Number of multi-network pod creations.",
	}, []string{
		LabelOutcome,
	})
	MultiNetworkIpamEvent = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: Namespace,
		Subsystem: subsystemMultiNetwork,
		Name:      "ipam_events_total",
		Help:      "Number of IPAM events received.",
	}, []string{
		labelNetwork,
		LabelAction,
		LabelDatapathFamily,
	})
	return []prometheus.Collector{
		MultiNetworkEndpoint,
		MultiNetworkPodCreation,
		MultiNetworkIpamEvent,
	}
}
