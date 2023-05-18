// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/cilium/cilium/global-peer/cmd/serve"
	ciliumversion "github.com/cilium/cilium/pkg/version"
)

// New creates a new global-peer command.
func New() *cobra.Command {
	rootCmd := &cobra.Command{
		Use:          "global-peer",
		Short:        "global-peer is an implementation of hubble Peer service of ABM clusters",
		Long:         "global-peer is an implementation of hubble Peer service of ABM clusters",
		SilenceUsage: true,
		Version:      ciliumversion.GetCiliumVersion().Version,
	}
	vp := newViper()

	rootCmd.AddCommand(
		serve.New(vp),
	)
	rootCmd.SetVersionTemplate("{{with .Name}}{{printf \"%s \" .}}{{end}}{{printf \"v%s\" .Version}}\n")
	return rootCmd
}

func newViper() *viper.Viper {
	vp := viper.New()
	vp.SetEnvPrefix("peer")
	vp.AutomaticEnv()
	return vp
}
