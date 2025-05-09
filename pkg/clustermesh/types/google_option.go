// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import (
	flag "github.com/spf13/pflag"
)

// ClusterInfo groups together the ClusterID and the ClusterName
type GoogleClusterInfo struct {
	EnableGDCILB               bool     `mapstructure:"enable-gdc-ilb"`
	DisableClustermeshNodeSync bool     `mapstructure:"disable-clustermesh-node-sync"`
	SyncMultiNicEPs            bool     `mapstructure:"sync-multi-nic-eps"`
	NamespaceLabels            []string `mapstructure:"clustermesh-namespace-labels"`
}

// DefaultGoogleClusterInfo represents the default GoogleClusterInfo values.
var DefaultGoogleClusterInfo = GoogleClusterInfo{
	EnableGDCILB:               false,
	DisableClustermeshNodeSync: false,
	SyncMultiNicEPs:            true,
	NamespaceLabels:            nil,
}

// Flags implements the cell.Flagger interface, to register the given flags.
func (def GoogleClusterInfo) Flags(flags *flag.FlagSet) {
	flags.Bool("enable-gdc-ilb", def.EnableGDCILB, "Enable google GDC-H ILB Support")
	flags.Bool("disable-clustermesh-node-sync", def.DisableClustermeshNodeSync, "Disable node sync on the clustermesh")
	flags.Bool("sync-multi-nic-eps", def.SyncMultiNicEPs, "Sync multi-nic endpoints")
	flags.StringSlice("clustermesh-namespace-labels", def.NamespaceLabels, "List of namespace labels to enable clustermesh distribution for (empty means all namespaces are distributed)")
}
