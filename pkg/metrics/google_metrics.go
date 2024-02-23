package metrics

import (
	"github.com/cilium/cilium/pkg/metrics/metric"
)

// Add Google-specific metrics to this file.
var (
	// Define metrics here. Do not delete this entry and comment.
	_ metric.Counter

	ConntrackGCDistribution = NoOpObserverVec
)

const (
	subsystemWireguard = "wireguard"
	subsystemDatapath  = "google_datapath"
)

var (
	// Metrics for In-transit Encryption
	WireguardPeersTotal         = NoOpGaugeVec
	WireguardAgentTimeStats     = NoOpObserverVec
	WireguardTransferBytesTotal = NoOpGaugeVec
)

type GoogleMetrics struct {
	ConntrackGCDistribution metric.Vec[metric.Observer]
	// Metrics for In-transit Encryption
	WireguardPeersTotalEnabled         metric.Vec[metric.Gauge]
	WireguardAgentTimeStatsEnabled     metric.Vec[metric.Observer]
	WireguardTransferBytesTotalEnabled metric.Vec[metric.Gauge]
}

func NewGoogleMetrics() *GoogleMetrics {
	gm := &GoogleMetrics{
		WireguardPeersTotalEnabled: metric.NewGaugeVec(metric.GaugeOpts{
			ConfigName: Namespace + "_" + subsystemWireguard + "_peers_total",
			Namespace:  Namespace,
			Subsystem:  subsystemWireguard,
			Name:       "peers_total",
			Help:       "Total number of Wireguard peers.",
		}, []string{
			LabelSourceNodeName,
		}),
		WireguardAgentTimeStatsEnabled: metric.NewHistogramVec(metric.HistogramOpts{
			ConfigName: Namespace + "_" + subsystemWireguard + "_wireguard_agent_time_stats_seconds",
			Namespace:  Namespace,
			Subsystem:  subsystemWireguard,
			Name:       "wireguard_agent_time_stats_seconds",
			Help:       "Duration it takes to perform various wireguard management activities via the agent.",
		}, []string{
			LabelSourceNodeName,
			LabelScope,
		}),
		WireguardTransferBytesTotalEnabled: metric.NewGaugeVec(metric.GaugeOpts{
			ConfigName: Namespace + "_" + subsystemWireguard + "_transfer_bytes_total",
			Namespace:  Namespace,
			Subsystem:  subsystemWireguard,
			Name:       "transfer_bytes_total",
			Help:       "Total number of bytes transferred via the Wireguard interface.",
		}, []string{
			LabelSourceNodeName,
			LabelTargetNodeName,
			LabelType,
		}),
		ConntrackGCDistribution: metric.NewHistogramVec(metric.HistogramOpts{
			ConfigName: Namespace + "_" + subsystemDatapath + "_conntrack_gc_distribution",
			Namespace:  Namespace,
			Subsystem:  subsystemDatapath,
			Name:       "conntrack_gc_distribution",
			Help:       "The distribution of deleted conntrack entries at the end of a garbage collector run labeled by datapath family.",
		}, []string{
			LabelDatapathFamily,
			LabelProtocol,
		}),
		// Add metrics here. Do not delete this comment.
	}

	WireguardPeersTotal = gm.WireguardPeersTotalEnabled
	WireguardAgentTimeStats = gm.WireguardAgentTimeStatsEnabled
	WireguardTransferBytesTotal = gm.WireguardTransferBytesTotalEnabled
	ConntrackGCDistribution = gm.ConntrackGCDistribution

	return gm
}
