package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
)

const (
	subsystemMultiNetwork    = "google_multinet"
	subsystemServiceSteering = "google_service_steering"
	subsystemPersistentIP    = "google_persistent_ip"

	labelNetwork     = "network"
	labelNetworkType = "network_type"

	labelReconcileType = "reconcile_type"
)

var (
	MultiNetworkEndpoint    = NoOpGaugeVec
	MultiNetworkPodCreation = NoOpCounterVec
	MultiNetworkIpamEvent   = NoOpCounterVec

	ServiceSteeringEndpoint        = NoOpGauge
	ServiceSteeringReconcileTotal  = NoOpCounterVec
	ServiceSteeringReconcileErrors = NoOpCounterVec

	PersistentIPEndpointsTotal = NoOpGaugeVec
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

	ServiceSteeringEndpoint = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: Namespace,
		Subsystem: subsystemServiceSteering,
		Name:      "endpoints_total",
		Help:      "Number of endpoints selected by a traffic selector.",
	})

	ServiceSteeringReconcileTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: Namespace,
		Subsystem: subsystemServiceSteering,
		Name:      "reconcile_total",
		Help:      "Number of reconciliations per type.",
	}, []string{
		labelReconcileType,
		LabelOutcome,
	})

	PersistentIPEndpointsTotal = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: Namespace,
		Subsystem: subsystemPersistentIP,
		Name:      "pip_endpoints_total",
		Help:      "Number of persistent-ip endpoints per IP family and network.",
	}, []string{
		LabelDatapathFamily,
		labelNetwork,
	})

	return []prometheus.Collector{
		MultiNetworkEndpoint,
		MultiNetworkPodCreation,
		MultiNetworkIpamEvent,
		ServiceSteeringEndpoint,
		ServiceSteeringReconcileTotal,
		PersistentIPEndpointsTotal,
	}
}
