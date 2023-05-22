// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package globalpeerdefaults

import (
	"fmt"
	"time"

	ciliumdefaults "github.com/cilium/cilium/pkg/defaults"
	hubbledefaults "github.com/cilium/cilium/pkg/hubble/defaults"
)

const (
	// ConfigPath is the default config path for global-peer.
	ConfigPath = "/etc/global-peer/config.yaml"
	// ClusterName is the default cluster name
	ClusterName = ciliumdefaults.ClusterName
	// LocalPeerTarget is the address of the peer service.
	LocalPeerTarget = "hubble-peer.kube-system.svc.cluster.local:443"
	// DialTimeout is the timeout that is used when establishing a new
	// connection.
	DialTimeout = 5 * time.Second
	// RetryTimeout is the duration to wait between reconnection attempts.
	RetryTimeout = 30 * time.Second
)

var (
	// ListenAddress is the address on which the Hubble Global Peer server
	// listens for incoming gRPC requests.
	ListenAddress = fmt.Sprintf(":%d", hubbledefaults.ServerPort)
)
