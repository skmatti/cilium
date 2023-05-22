// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package server

import (
	"context"
	"io"

	peerpb "github.com/cilium/cilium/api/v1/peer"
	peertypes "github.com/cilium/cilium/pkg/hubble/peer/types"
	"github.com/cilium/cilium/pkg/hubble/testutils"
	"google.golang.org/grpc"
)

func newSpyPeerClientBuilder(ch chan *peerpb.ChangeNotification) peertypes.ClientBuilder {
	return &testutils.FakePeerClientBuilder{
		OnClient: func(target string) (peertypes.Client, error) {
			return &testutils.FakePeerClient{
				OnNotify: func(_ context.Context, _ *peerpb.NotifyRequest, _ ...grpc.CallOption) (peerpb.Peer_NotifyClient, error) {
					return &testutils.FakePeerNotifyClient{
						OnRecv: func() (*peerpb.ChangeNotification, error) {
							msg, ok := <-ch
							if !ok {
								return nil, io.EOF
							}
							return msg, nil
						},
					}, nil
				},
				OnClose: func() error {
					return nil
				},
			}, nil
		},
	}
}
