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

//go:build !privileged_tests
// +build !privileged_tests

package aggregator

import (
	"fmt"
	"strconv"
	"testing"
	"time"
)

const (
	testAggregationInterval = 5 * time.Second
	testAggregationTick     = time.Second
	testCapacity            = 5
)

type testEvent struct {
	name string
}

func (e *testEvent) AggregationKey() interface{} {
	return fmt.Sprintf("%s", e.name)
}

// TestAggregator tests the aggregator can aggregates the events with the correct
// count and max capacity. When the output channel is busy, it drops the events and
// increments the drop counter.
func TestAggregator(t *testing.T) {
	expireCh := make(chan *AggregatorEntry)
	var queueDrop int
	a := NewAggregator(testAggregationInterval, testAggregationTick, testCapacity, expireCh, func() { queueDrop++ })
	a.Start()

	testName := "test"
	repeats := 10
	// When the same event arrives for repeats times, we should get one expired entry with the count equals to repeats.
	cnt := 0
	for cnt < repeats {
		if err := a.Aggregate(&testEvent{name: testName}); err != nil {
			t.Errorf("Aggregate() = %v, want nil", err)
		}
		cnt++
	}
	ae := <-expireCh
	received := ae.Entry.(*testEvent)
	if received.name != testName || ae.Count != repeats {
		t.Errorf("Received aggregated event= (%v, %v), want (%v, %v)",
			received.name, ae.Count, testName, repeats)
	}

	// When different events arrive, aggregate should succeed for the first testCapacity events and then fails.
	cnt = 0
	for cnt < testCapacity {
		ev := &testEvent{name: testName + strconv.Itoa(cnt)}
		if err := a.Aggregate(ev); err != nil {
			t.Errorf("Aggregate(%v) = %v, want nil", ev, err)
		}
		cnt++
	}
	ev := &testEvent{name: testName}
	if err := a.Aggregate(ev); err == nil {
		t.Errorf("Aggregate(%v) = nil,  want %v", ev, fmt.Errorf("aggregator cache full!"))
	}
	<-expireCh
	// Multiple events should arrive on expireCh, but because we only receive one here,
	// the rest is expected to drop. Wait here so that the queueDrop counter will have time
	// to increment.
	time.Sleep(2 * time.Second)
	if queueDrop != testCapacity-1 {
		t.Errorf("queueDrop = %d,  want %d", queueDrop, testCapacity-1)
	}
}
