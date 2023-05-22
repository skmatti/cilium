// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package serve

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	globalpeerdefaults "github.com/cilium/cilium/pkg/hubble/global-peer/defaults"
	"github.com/cilium/cilium/pkg/hubble/global-peer/server"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

const (
	keyDebug            = "debug"
	keyConfigPath       = "config"
	keyClusterName      = "cluster-name"
	keyListenAddress    = "org-peer-listen-address"
	keyDialTimeout      = "dial-timeout"
	keyRetryTimeout     = "retry-timeout"
	keyLocalPeerService = "local-peer-service"
)

// New creates a new serve command.
func New(vp *viper.Viper) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Run the gRPC server",
		Long:  `Run the gRPC server with Hubble Peer interface.`,
		RunE: func(_ *cobra.Command, _ []string) error {
			return runServe(context.Background(), vp)
		},
	}
	flags := cmd.Flags()
	flags.Bool(
		keyDebug,
		false,
		"Enable debug messages",
	)
	flags.String(
		keyConfigPath,
		globalpeerdefaults.ConfigPath,
		"Path to config file",
	)
	flags.String(
		keyClusterName,
		globalpeerdefaults.ClusterName,
		"Name of the current cluster",
	)
	flags.String(
		keyListenAddress,
		globalpeerdefaults.ListenAddress,
		"Address on which to listen",
	)
	flags.Duration(
		keyDialTimeout,
		globalpeerdefaults.DialTimeout,
		"Dial timeout when connecting to hubble peers",
	)
	flags.String(
		keyLocalPeerService,
		globalpeerdefaults.LocalPeerTarget,
		"Address of the server that implements the peer gRPC service",
	)
	flags.Duration(
		keyRetryTimeout,
		globalpeerdefaults.RetryTimeout,
		"Time to wait before attempting to reconnect to a hubble peer when the connection is lost",
	)
	vp.BindPFlags(flags)

	return cmd
}

func runServe(ctx context.Context, vp *viper.Viper) error {
	if vp.GetBool(keyDebug) {
		logging.SetLogLevelToDebug()
	}
	logger := logging.DefaultLogger.WithField(logfields.LogSubsys, "global-peer")
	vp.SetConfigFile(vp.GetString(keyConfigPath))
	if err := vp.MergeInConfig(); err != nil {
		return fmt.Errorf("failed to parse %q config: %v", vp.GetString(keyConfigPath), err)
	}

	opts := server.Options{
		ClusterName:   vp.GetString(keyClusterName),
		ListenAddress: vp.GetString(keyListenAddress),
		DialTimeout:   vp.GetDuration(keyDialTimeout),
		RetryTimeout:  vp.GetDuration(keyRetryTimeout),
		PeerTarget:    vp.GetString(keyLocalPeerService),
	}

	srv, err := server.New(logger, opts)
	if err != nil {
		return fmt.Errorf("cannot create global-peer server: %v", err)
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	go func() {
		sigs := make(chan os.Signal, 1)
		signal.Notify(sigs, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)
		select {
		case s := <-sigs:
			logger.Infof("Closing server due to signal %v", s)
			cancel()
		case <-ctx.Done():
			logger.Debug("Closing server due to context")
		}
	}()
	return srv.Run(ctx)
}
