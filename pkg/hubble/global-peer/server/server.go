// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package server

import (
	"context"
	"fmt"

	"github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"

	"github.com/cilium/cilium/pkg/gke/client/nodepool/clientset/versioned"
	"github.com/cilium/cilium/pkg/hubble/peer"
	"github.com/cilium/cilium/pkg/hubble/peer/serviceoption"
	peerTypes "github.com/cilium/cilium/pkg/hubble/peer/types"
	"github.com/cilium/cilium/pkg/hubble/server"
	"github.com/cilium/cilium/pkg/hubble/server/serveroption"
	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

// Server provides implementation Hubble Peer backed by ABM NodePools and
// another instance of Hubble Peer in the local cluster.
type Server struct {
	server       *server.Server
	peerNotifier *globalPeerNotifier
	opts         Options
	log          logrus.FieldLogger
}

// New creates a new Server.
func New(log logrus.FieldLogger, opts Options) (*Server, error) {
	kubeConfig, err := k8s.CreateConfig()
	if err != nil {
		return nil, err
	}

	kubeClient, err := versioned.NewForConfig(kubeConfig)
	if err != nil {
		return nil, fmt.Errorf("Failed to create global peer client: %v", err)
	}

	globalPeerNotifier, err := NewGlobalPeerNotifier(log, kubeClient, opts)
	if err != nil {
		return nil, err
	}

	// TODO(b/277353950): pass TLS info to the client
	peerSvc := peer.NewService(globalPeerNotifier, serviceoption.WithoutTLSInfo())

	address := opts.ListenAddress
	// TODO(b/277353950): pass TLS info to the server
	srvOptions := []serveroption.Option{
		serveroption.WithTCPListener(address),
		serveroption.WithPeerService(peerSvc),
		serveroption.WithInsecure(),
	}
	srvLog := logging.DefaultLogger.WithField(logfields.LogSubsys, "hubble-server")
	srv, err := server.NewServer(srvLog, srvOptions...)
	if err != nil {
		return nil, err
	}

	return &Server{
		server:       srv,
		peerNotifier: globalPeerNotifier,
		opts:         opts,
		log:          log,
	}, nil
}

// Run starts the global-peer server. Run does not return unless a
// listening fails with fatal errors.
func (s *Server) Run(ctx context.Context) error {
	group, localCtx := errgroup.WithContext(ctx)

	group.Go(func() error {
		s.log.Info("Starting listening for changes to NodePools")
		s.peerNotifier.Run(localCtx)
		return fmt.Errorf("NodePool informer: %w", localCtx.Err())
	})

	group.Go(func() error {
		s.log.WithField("address", s.opts.ListenAddress).Info("Starting Hubble Global Peer server")
		return s.server.Serve()
	})

	group.Go(func() error {
		<-localCtx.Done()
		s.log.Info("Stopping server...")
		s.server.Stop()
		s.log.Info("Server stopped")
		return nil
	})

	group.Go(func() error {
		s.log.WithField("address", s.opts.PeerTarget).Info("Starting client to local Hubble Peer")
		peerClientBuilder := &peerTypes.RemoteClientBuilder{
			DialTimeout: s.opts.DialTimeout,
		}
		return s.peerNotifier.watchNotifications(localCtx, peerClientBuilder)
	})

	return group.Wait()
}
