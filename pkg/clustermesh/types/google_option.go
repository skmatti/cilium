// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import (
	flag "github.com/spf13/pflag"
)

// GoogleConfig contains Google-specific clustermesh configuration.
type GoogleConfig struct {
	EnableGDCILB               bool     `mapstructure:"enable-gdc-ilb"`
	DisableClustermeshNodeSync bool     `mapstructure:"disable-clustermesh-node-sync"`
	SyncMultiNicEPs            bool     `mapstructure:"sync-multi-nic-eps"`
	NamespaceLabels            []string `mapstructure:"clustermesh-namespace-labels"`
}

// DefaultGoogleConfig represents the default configuration.
var DefaultGoogleConfig = GoogleConfig{
	EnableGDCILB:               false,
	DisableClustermeshNodeSync: false,
	SyncMultiNicEPs:            false,
	NamespaceLabels:            nil,
}

// Flags implements the cell.Flagger interface, to register the given flags.
func (def GoogleConfig) Flags(flags *flag.FlagSet) {
	flags.Bool("enable-gdc-ilb", def.EnableGDCILB, "Enable Google GDC ILB support")
	flags.Bool("disable-clustermesh-node-sync", def.DisableClustermeshNodeSync, "Disable syncing of CiliumNode resources to the clustermesh")
	flags.Bool("sync-multi-nic-eps", def.SyncMultiNicEPs, "Enable syncing of multi-NIC endpoints to the clustermesh")
	flags.StringSlice("clustermesh-namespace-labels", def.NamespaceLabels, "List of namespace labels to enable clustermesh distribution for. If empty, all namespaces are selected.")
}
