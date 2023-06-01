package metrics

import (
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/prometheus/client_golang/prometheus"
)

const (
	SubsystemMultiNetwork = "google_multinet"
	LabelNetwork          = "network"
	LabelNetworkType      = "network_type"
)

var (
	MultiNetworkEndpoint    = NoOpGaugeVec
	MultiNetworkPodCreation = NoOpCounterVec
	MultiNetworkIpamEvent   = NoOpCounterVec

	log = logging.DefaultLogger.WithField(logfields.LogSubsys, "metrics")
)

func init() {
	collectors := initGoogleMetrics()
	MustRegister(collectors...)
}

func initGoogleMetrics() []prometheus.Collector {
	MultiNetworkEndpoint = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: Namespace,
		Subsystem: SubsystemMultiNetwork,
		Name:      "endpoints_total",
		Help:      "Number of multi-network endpoints managed by this agent.",
	}, []string{
		LabelNetwork,
		LabelNetworkType,
	})
	MultiNetworkPodCreation = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: Namespace,
		Subsystem: SubsystemMultiNetwork,
		Name:      "pod_creations_total",
		Help:      "Number of multi-network pod creations.",
	}, []string{
		LabelOutcome,
	})
	MultiNetworkIpamEvent = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: Namespace,
		Subsystem: SubsystemMultiNetwork,
		Name:      "ipam_events_total",
		Help:      "Number of IPAM events received.",
	}, []string{
		LabelNetwork,
		LabelAction,
		LabelDatapathFamily,
	})
	return []prometheus.Collector{
		MultiNetworkEndpoint,
		MultiNetworkPodCreation,
		MultiNetworkIpamEvent,
	}
}
