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

package ratelimiter

import (
	"testing"
	"time"
)

const (
	testRate     = 60
	testMax      = 180
	testInterval = time.Second
)

// TestRateLimiter verifies that the rate limiter follows the configured rate
// and token max.
func TestRateLimiter(t *testing.T) {
	r := NewRateLimiter(testRate, testMax, testInterval)
	r.Start()
	// Verify that events within the rate would be allowed.
	cnt := 0
	for cnt < testRate {
		if ok := r.Allow(); !ok {
			t.Errorf("Allow() = %v, want true", ok)
		}
		cnt++
	}
	// Verify events exceeding the rate would not be allowed.
	if ok := r.Allow(); ok {
		t.Errorf("Allow() = %v, want false", ok)
	}
	// Sleep so that the token can be accumulated to max.
	time.Sleep(5 * time.Second)
	// Verify that burst events are allowed at max rate.
	cnt = 0
	for cnt < testMax {
		if ok := r.Allow(); !ok {
			t.Errorf("Allow() = %v, want true", ok)
		}
		cnt++
	}
	// Verify that burst events exceeding the max rate would not be allowed.
	if ok := r.Allow(); ok {
		t.Errorf("Allow() = %v, want false", ok)
	}
	r.Stop()
}
