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

package timewheel

import (
	"time"

	"github.com/cilium/cilium/pkg/lock"
)

// Timewheel allows user to use one go routine to handle multiple timer events.
// The events are stored in the timewheel with their respective expire time.
// the Expire function for the event will be triggered after a event reaches its expire time.
type Timewheel struct {
	// interval decides how frequently the ticker is run and thus
	// the resolution of the timewheel. It's a fixed value for a timewheel.
	interval time.Duration
	ticker   *time.Ticker
	stop     chan struct{}

	lock lock.Mutex
	// slots is the map that stores all timed events.
	// The key is equivalent to time in terms of the number of intervals.
	slots map[int64]*slot
	pos   int64 // slot position corresponding to current time
}

// Slot stores all events for a give time slot.
type slot struct {
	entries map[int64]Entry
	pos     int64
}

// Key allows one to retrieve a stored event.
type Key struct {
	slotPos  int64 // id of the slot
	entryPos int64 // id of the entry within the slot
}

// Expire is the function to be called when the event timer expires.
type Entry interface {
	Expire()
}

// NewTimewheel returns an new instance of Timewheel which ticks at interval.
func NewTimewheel(interval time.Duration) *Timewheel {
	return &Timewheel{
		interval: interval,
		slots:    make(map[int64]*slot),
		pos:      0,
	}
}

// Start starts the Timewheel
func (tw *Timewheel) Start() {
	tw.ticker = time.NewTicker(tw.interval)
	tw.stop = make(chan struct{})
	go tw.start()
}

func (tw *Timewheel) start() {
	for {
		select {
		case <-tw.ticker.C:
			tw.tickHandler()
		case <-tw.stop:
			tw.ticker.Stop()
			return
		}
	}
}

func (tw *Timewheel) tickHandler() {
	tw.lock.Lock()
	s, ok := tw.slots[tw.pos]
	if !ok {
		tw.pos++
		tw.lock.Unlock()
		return
	}
	delete(tw.slots, tw.pos)
	tw.pos++
	tw.lock.Unlock()

	for _, e := range s.entries {
		e.Expire()
	}
	return
}

// Stop stops the Timewheel.
func (tw *Timewheel) Stop() {
	close(tw.stop)
}

// Clear clears all existing events.
func (tw *Timewheel) Clear() {
	tw.lock.Lock()
	defer tw.lock.Unlock()
	tw.slots = make(map[int64]*slot)
}

func (tw *Timewheel) insert(e Entry, pos int64) *Key {
	s, ok := tw.slots[pos]
	if ok {
		s.pos++
	} else {
		s = &slot{entries: make(map[int64]Entry), pos: 1}
		tw.slots[pos] = s
	}
	s.entries[s.pos] = e
	return &Key{slotPos: pos, entryPos: s.pos}
}

// Add adds an Entry to the Timewheel and returns the key.
func (tw *Timewheel) Add(e Entry, delay time.Duration) (k *Key) {
	tw.lock.Lock()
	defer tw.lock.Unlock()
	pos := tw.pos + int64(delay.Seconds()/tw.interval.Seconds())
	return tw.insert(e, pos)
}

// Remove removes the entry with key k from the timewheel.
func (tw *Timewheel) Remove(k *Key) bool {
	tw.lock.Lock()
	defer tw.lock.Unlock()
	if k.slotPos < tw.pos {
		return false
	}
	if slot, ok := tw.slots[k.slotPos]; ok {
		if _, ok := slot.entries[k.entryPos]; ok {
			delete(slot.entries, k.entryPos)
			return true
		}
	}
	return false
}

// Update updates the entry with k with a new delay from now.
func (tw *Timewheel) Update(k *Key, delay time.Duration) *Key {
	tw.lock.Lock()
	defer tw.lock.Unlock()
	if k.slotPos < tw.pos {
		return nil
	}
	pos := tw.pos + int64(delay.Seconds()/tw.interval.Seconds())
	if k.slotPos == pos {
		//no update
		return k
	}
	if slot, ok := tw.slots[k.slotPos]; ok {
		if e, ok := slot.entries[k.entryPos]; ok {
			delete(slot.entries, k.entryPos)
			return tw.insert(e, pos)
		}
	}
	return nil
}
