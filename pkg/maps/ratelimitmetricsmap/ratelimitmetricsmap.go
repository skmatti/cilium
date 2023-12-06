// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ratelimitmetricsmap

import (
	"unsafe"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/cilium/cilium/pkg/ebpf"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/metrics"
)

var Cell = cell.Module(
	"ratelimitmetricsmap",
	"eBPF Ratelimit Metrics Map",
	cell.Invoke(RegisterCollector),
)

// IterateCallback represents the signature of the callback function expected by
// the IterateWithCallback method, which in turn is used to iterate all the
// keys/values of a ratelimit metrics map.
type IterateCallback func(*Key, *Value)

// RatelimitMetricsMap interface represents a ratelimit metrics map, and can be reused
// to implement mock maps for unit tests.
type RatelimitMetricsMap interface {
	IterateWithCallback(IterateCallback) error
}

type ratelimitMetricsMap struct {
	*ebpf.Map
}

var (
	// RatelimitMetrics is the bpf ratelimit metrics map.
	RatelimitMetrics = ratelimitMetricsMap{ebpf.NewMap(&ebpf.MapSpec{
		Name:       MapName,
		Type:       ebpf.Hash,
		KeySize:    uint32(unsafe.Sizeof(Key{})),
		ValueSize:  uint32(unsafe.Sizeof(Value{})),
		MaxEntries: MaxEntries,
		Pinning:    ebpf.PinByName,
	})}
	log = logging.DefaultLogger.WithField(logfields.LogSubsys, "ratelimit-map-metrics")
)

const (
	// MapName for ratelimit metrics map.
	MapName = "cilium_ratelimit_metrics"
	// MaxEntries is the maximum number of keys that can be present in the
	// Ratelimit Metrics Map.
	MaxEntries = 64
)

// usageType represents source of ratelimiter usage in datapath code.
type usageType uint32

const (
	ICMPV6 usageType = iota + 1
	EVENTS_MAP
)

func (t usageType) String() string {
	switch t {
	case ICMPV6:
		return "icmpv6"
	case EVENTS_MAP:
		return "events"
	}

	return ""
}

// Key must be in sync with struct ratelimit_metrics_key in <bpf/lib/ratelimit.h>
type Key struct {
	Usage usageType `align:"usage"`
}

// Value must be in sync with struct ratelimit_metrics_value in <bpf/lib/ratelimit.h>
type Value struct {
	Dropped uint64 `align:"dropped"`
}

// IterateWithCallback iterates through all the keys/values of the ratelimit metrics map,
// passing each key/value pair to the cb callback
func (rm ratelimitMetricsMap) IterateWithCallback(cb IterateCallback) error {
	return rm.Map.IterateWithCallback(&Key{}, &Value{}, func(k, v interface{}) {
		key := k.(*Key)
		value := v.(*Value)
		cb(key, value)
	})
}

// ratelimitMetricsMapCollector implements Prometheus Collector interface
type ratelimitMetricsMapCollector struct {
	mutex lock.Mutex

	droppedDesc *prometheus.Desc
	droppedMap  map[usageType]float64
}

func newRatelimitMetricsMapCollector() *ratelimitMetricsMapCollector {
	return &ratelimitMetricsMapCollector{
		droppedMap: make(map[usageType]float64),
		droppedDesc: prometheus.NewDesc(
			prometheus.BuildFQName(metrics.Namespace, "", "bpf_ratelimit_dropped_total"),
			"Total drops resulting from BPF ratelimiter, tagged by source of drop",
			[]string{"usage"}, nil,
		),
	}
}

func (rc *ratelimitMetricsMapCollector) Collect(ch chan<- prometheus.Metric) {
	rc.mutex.Lock()
	defer rc.mutex.Unlock()

	err := RatelimitMetrics.IterateWithCallback(func(k *Key, val *Value) {
		rc.droppedMap[k.Usage] = float64(val.Dropped)
	})
	if err != nil {
		log.WithError(err).Warn("Failed to read ratelimit metrics from BPF map")
		// Do not update partial metrics
		return
	}

	for usage, val := range rc.droppedMap {
		rc.updateCounterMetric(rc.droppedDesc, ch, val, usage.String())
	}
}

func (rc *ratelimitMetricsMapCollector) updateCounterMetric(desc *prometheus.Desc, ch chan<- prometheus.Metric, value float64, labelValues ...string) {
	ch <- prometheus.MustNewConstMetric(desc, prometheus.CounterValue, value, labelValues...)
}

func (rc *ratelimitMetricsMapCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- rc.droppedDesc
}

func RegisterCollector() {
	if err := metrics.Register(newRatelimitMetricsMapCollector()); err != nil {
		log.WithError(err).Error("Failed to register ratelimit metrics map collector to Prometheus registry. " +
			"BPF ratelimit metrics will not be collected")
	}
}
