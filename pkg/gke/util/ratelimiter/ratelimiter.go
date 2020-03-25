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

package ratelimiter

import (
	"time"

	"github.com/cilium/cilium/pkg/lock"
)

// RateLimiter implements a simple bucket-based rate limiter.
// For each interval, the number of token is increased by rate with a cap max.
// A call to Allow will return true if token is > 0 and decrement the token by 1.
type RateLimiter struct {
	ticker   *time.Ticker
	interval time.Duration
	stop     chan struct{}

	lock   lock.Mutex
	rate   uint
	max    uint
	tokens uint
}

// NewRateLimiter returns a rate limiter with the average rate/interval
// and max token allowed which corresponds to the burst rate.
func NewRateLimiter(rate, max uint, interval time.Duration) *RateLimiter {
	return &RateLimiter{
		interval: interval,
		max:      max,
		rate:     rate,
	}
}

// fill increments the tokens by r.rate every interval time until it reaches max.
func (r *RateLimiter) fill() {
	r.lock.Lock()
	defer r.lock.Unlock()
	r.tokens = r.tokens + r.rate
	if r.tokens > r.max {
		r.tokens = r.max
	}
}

// Allow returns true if an event happens at the rate within the limit (tokens > 0).
func (r *RateLimiter) Allow() bool {
	r.lock.Lock()
	defer r.lock.Unlock()
	if r.tokens >= 1 {
		r.tokens = r.tokens - 1
		return true
	}
	return false

}

// Start starts the rate limiter time ticker.
func (r *RateLimiter) Start() {
	r.ticker = time.NewTicker(r.interval)
	r.fill()
	r.stop = make(chan struct{})
	go r.start()
}

// Update updates the parameters of the rate limiter.
func (r *RateLimiter) Update(rate, max uint) {
	r.lock.Lock()
	defer r.lock.Unlock()
	r.rate = rate
	r.max = max
	if r.tokens > r.max {
		r.tokens = r.max
	}
}

// start starts the ticker and the regular bucket filling routine.
func (r *RateLimiter) start() {
	for {
		select {
		case <-r.ticker.C:
			r.fill()
		case <-r.stop:
			r.ticker.Stop()
			return
		}
	}
}

// Stop stops the rate limiter go routine.
// Stop must be called to avoid leaking the RateLimiter.
func (r *RateLimiter) Stop() {
	close(r.stop)
}
