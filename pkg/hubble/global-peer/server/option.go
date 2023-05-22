// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package server

import "time"

// Options stores all the configuration values for the global-peer server.
type Options struct {
	ListenAddress string
	ClusterName   string
	PeerTarget    string
	DialTimeout   time.Duration
	RetryTimeout  time.Duration
}
