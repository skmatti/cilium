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

package policylogger

import (
	"fmt"
	"sync/atomic"
)

type counter uint64

// counters on the flow processing path. All the counters are cumulative.
// Note that counter will count only if logging is enabled for either allow or deny.
type counters struct {
	// allowedConnections counts the total number of allowed connections.
	allowedConnections counter
	// deniedConnections counts the total number of denied connections.
	deniedConnections counter
	// generatedLogs counts the number of generated logs.
	generatedLogs counter
	// rateLimitDroppedLogs counts the number of logs dropped due to rate limiting.
	rateLimitDroppedLogs counter
	// rateLimitDroppedConnections counts the number of connections records dropped due to rate limiting.
	rateLimitDroppedConnections counter
	// aggregateFails counts the number of failures when aggregator fails to accept the log.
	// The logs are dropped after the failure.
	aggregateFails counter
	// logWriteFails counts the number of failures when writer writes the log.
	logWriteFails counter
	// flowParseFails counts the number of failures in flow parsing.
	flowParseFails counter
	// typeErrors counts the number of errors due to type conversion and marshall, which should
	// not happen.
	typeErrors counter
	// storeErrors counts the number of errors due to k8s store not found or k8s object not found.
	storeErrors counter
}

// inc atomically increments a counter so that the metrics tracking can be done without lock.
func (c *counter) inc(delta uint64) {
	atomic.AddUint64((*uint64)(c), delta)
}

// inc atomically gets a counter value without the need of a lock.
func (c *counter) get() uint64 {
	return atomic.LoadUint64((*uint64)(c))
}

// counterDiff is the difference of two counters.
type counterDiff counters

// sub subtracts another counter to generate counterDiff
func (c *counters) sub(other *counters) *counterDiff {
	diff := &counterDiff{}
	diff.allowedConnections = c.allowedConnections - other.allowedConnections
	diff.deniedConnections = c.deniedConnections - other.deniedConnections
	diff.generatedLogs = c.generatedLogs - other.generatedLogs
	diff.rateLimitDroppedLogs = c.rateLimitDroppedLogs - other.rateLimitDroppedLogs
	diff.rateLimitDroppedConnections = c.rateLimitDroppedConnections - other.rateLimitDroppedConnections
	diff.aggregateFails = c.aggregateFails - other.aggregateFails
	diff.logWriteFails = c.logWriteFails - other.logWriteFails
	diff.flowParseFails = c.flowParseFails - other.flowParseFails
	diff.typeErrors = c.typeErrors - other.typeErrors
	diff.storeErrors = c.storeErrors - other.storeErrors
	return diff
}

// formatMsg show the message to display for a counterDiff
// If errOnly is true, only the error counterDiff values will be put into the message.
func (c *counterDiff) formatMsg(errOnly bool) []string {
	var msg []string
	if !errOnly && c.allowedConnections > 0 {
		msg = append(msg, fmt.Sprintf("allowedConnections: +%d", c.allowedConnections))
	}
	if c.deniedConnections > 0 {
		msg = append(msg, fmt.Sprintf("deniedConnections: +%d", c.deniedConnections))
	}
	if !errOnly && c.generatedLogs > 0 {
		msg = append(msg, fmt.Sprintf("generatedLogs: +%d", c.generatedLogs))
	}
	if c.rateLimitDroppedLogs > 0 {
		msg = append(msg, fmt.Sprintf("rateLimitDroppedLogs: +%d", c.rateLimitDroppedLogs))
	}
	if c.rateLimitDroppedConnections > 0 {
		msg = append(msg, fmt.Sprintf("rateLimitDroppedConnections: +%d", c.rateLimitDroppedConnections))
	}
	if c.aggregateFails > 0 {
		msg = append(msg, fmt.Sprintf("aggregateFails: +%d", c.aggregateFails))
	}
	if c.logWriteFails > 0 {
		msg = append(msg, fmt.Sprintf("logWriteFails: +%d", c.logWriteFails))
	}
	if c.flowParseFails > 0 {
		msg = append(msg, fmt.Sprintf("flowParseFails: +%d", c.flowParseFails))
	}
	if c.typeErrors > 0 {
		msg = append(msg, fmt.Sprintf("typeErrors: +%d", c.typeErrors))
	}
	if c.storeErrors > 0 {
		msg = append(msg, fmt.Sprintf("storeErrors: +%d", c.storeErrors))
	}
	return msg
}
