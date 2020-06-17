// Copyright 2020 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package aggregator

import (
	"fmt"
	"time"

	"github.com/cilium/cilium/pkg/gke/util/timewheel"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/sirupsen/logrus"
)

var (
	log = logging.DefaultLogger.WithField(logfields.LogSubsys, "gke-util-aggregator")
)

// Aggregator implements a simple event aggregation algorithm. Multiple events with the same
// key will be aggregated into a single AggregatorEntry with event counts. After the interval
// time since the first appearance of the event, the event will be emitted with the number of
// occurrence during this interval.
type Aggregator struct {
	tw       *timewheel.Timewheel
	outputCh chan *AggregatorEntry

	// interval is the length of aggregation period. Value should be fixed after init.
	interval time.Duration
	// capacity is the maximum number of different entries that can be
	// stored in cache at the same time. Value should be fixed after init.
	capacity int
	// outputCh is the channel to output the events after the aggregation.
	// queueDrop counts the number of drops due to outputCh is full.
	queueDrop uint64

	lock lock.Mutex
	// cachedEntries stores all aggregate entries with AggregationKey.
	cachedEntries map[interface{}]*AggregatorEntry
}

// Event interface for aggregation.
type Event interface {
	// AggregationKey obtains the key for aggregation to be based on.
	// Events with the same aggregation key will be aggregated.
	AggregationKey() interface{}
}

// AggregatorEntry is the output event which contains the original event (first one) and
// the count of occurrence.
type AggregatorEntry struct {
	Entry Event
	Count int
	agg   *Aggregator
}

// Expire puts the AggregatorEntry into output channel after the aggregation period ends.
func (ae *AggregatorEntry) Expire() {
	ae.agg.lock.Lock()
	delete(ae.agg.cachedEntries, ae.Entry.AggregationKey())
	ae.agg.lock.Unlock()
	select {
	case ae.agg.outputCh <- ae:
	default:
		ae.agg.queueDrop++
		log.WithFields(logrus.Fields{"entry": ae.Entry, "cnt": ae.Count,
			"queueDrop": ae.agg.queueDrop}).Info("Queue full. Dropping aggregator entry.")
	}
	return
}

// NewAggregator creates a new aggregator. aggregateInterval is the interval of aggregation. tick decides the
// resolution of the aggregation timer. capacity is the maximum number of different entries the aggregator can
// store at the same time. outputCh is the output channel for aggregated events.
func NewAggregator(aggregateInterval, tick time.Duration, capacity int, outputCh chan *AggregatorEntry) *Aggregator {
	log.WithFields(logrus.Fields{"aggregateInterval": aggregateInterval, "capacity": capacity}).Info("New aggregator")
	ag := &Aggregator{
		cachedEntries: make(map[interface{}]*AggregatorEntry),
		interval:      aggregateInterval,
		capacity:      capacity,
		outputCh:      outputCh,
		tw:            timewheel.NewTimewheel(tick),
	}
	return ag
}

// Start starts the aggregator.
func (a *Aggregator) Start() {
	log.Info("Aggregator starts")
	a.tw.Start()
}

// Start stops the aggregator.
func (a *Aggregator) Stop() {
	log.Info("Aggregator stops")
	a.tw.Stop()
	a.tw.Clear()
}

// Aggregate aggregates the input event. If it is a new event, an AggregatorEntry is
// created and inserted it into cache with the expire timer in aggregateInterval. If
// the input has the same key with an existing entry, the counter is incremented.
func (a *Aggregator) Aggregate(e Event) error {
	key := e.AggregationKey()
	a.lock.Lock()
	if v, exist := a.cachedEntries[key]; exist {
		v.Count++
		a.lock.Unlock()
		return nil
	}
	if len(a.cachedEntries) == a.capacity {
		a.lock.Unlock()
		log.Infof("Skip caching an event as it exceeds the capacity")
		return fmt.Errorf("aggregator cache full!")
	}
	ae := &AggregatorEntry{Entry: e, Count: 1, agg: a}
	a.cachedEntries[key] = ae
	a.lock.Unlock()
	a.tw.Add(ae, a.interval)
	return nil
}
