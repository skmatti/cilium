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

// +build !privileged_tests

package timewheel

import (
	"fmt"
	"testing"
	"time"
)

type fakeEntry struct {
	label string
	ch    chan bool
}

func (fe *fakeEntry) Expire() {
	fmt.Printf("event %s expired at time %v\n", fe.label, time.Now())
	fe.ch <- true
}

// TestTimewheelAdd tests multiple timed events can be added to the timewheel
// and both will expire as expected.
func TestTimewheelAdd(t *testing.T) {
	ch := make(chan bool, 1)
	tw := NewTimewheel(time.Second)
	tw.Start()
	delay := time.Second * 2
	start := time.Now()
	key := tw.Add(&fakeEntry{label: "e1", ch: ch}, delay)
	t.Logf("Add event e1 with delay %v, key %v at time %v \n", delay, *key, start)
	key = tw.Add(&fakeEntry{label: "e2", ch: ch}, delay)
	t.Logf("Add event e2 with delay %v, key %v at time %v \n", delay, *key, start)
	<-ch
	<-ch
	elapsed := time.Since(start)
	t.Logf("Time elapsed since the start : %v", elapsed)
	if elapsed < delay || elapsed > delay+2*time.Second {
		t.Errorf("time.Since(start) = %v, want %v", elapsed, delay+time.Second)
	}
	tw.Stop()
}

// TestTimewheelUpdate tests an event timer can be updated.
func TestTimewheelUpdate(t *testing.T) {
	ch := make(chan bool, 1)
	tw := NewTimewheel(time.Second)
	tw.Start()
	start := time.Now()
	delay := time.Second * 2
	key := tw.Add(&fakeEntry{label: "e1", ch: ch}, delay)
	t.Logf("add event e1 with delay %v, key %v at time %v \n", delay, *key, time.Now())
	delay = delay * 2
	key = tw.Update(key, delay)
	t.Logf("update the event e1 with new delay %v, key %v at time %v \n", delay, *key, time.Now())
	<-ch
	elapsed := time.Since(start)
	t.Logf("Time elapsed since the start : %v", elapsed)
	if elapsed < delay || elapsed > delay+2*time.Second {
		t.Errorf("time.Since(start) = %v, want %v", elapsed, delay+time.Second)
	}
	tw.Stop()
}
