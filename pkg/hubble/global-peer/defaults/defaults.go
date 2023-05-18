// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package globalpeerdefaults

import (
	"fmt"

	ciliumdefaults "github.com/cilium/cilium/pkg/defaults"
	hubbledefaults "github.com/cilium/cilium/pkg/hubble/defaults"
)

const (
	// ConfigPath is the default config path for global-peer.
	ConfigPath = "/etc/global-peer/config.yaml"
	// ClusterName is the default cluster name
	ClusterName = ciliumdefaults.ClusterName
	// PeerTarget is the address of the peer service.
	PeerTarget = "unix://" + ciliumdefaults.HubbleSockPath
	// PeerServiceName is the name of the peer service, should it exist.
	PeerServiceName = "hubble-peer"
)

var (
	// ListenAddress is the address on which the Hubble Global Peer server
	// listens for incoming gRPC requests.
	ListenAddress = fmt.Sprintf(":%d", hubbledefaults.ServerPort)
)
