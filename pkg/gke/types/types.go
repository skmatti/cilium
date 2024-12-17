// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

// GCPSpec is the GCP specific CNI network configuration
type GCPSpec struct {
	// DatapathMode is the datapath mode for the interface created by the CNI plugin.
	DatapathMode string `json:"datapath-mode"`
	// IpamMode defines the IPAM mode to be used by the CNI plugin (delegated or internal).
	IpamMode string `json:"ipam-mode"`
	// EnableIPv4 is whether IPv4 addressing is enabled. If enabled, all endpoints are allocated an IPv4 address.
	EnableIPv4 bool `json:"enable-ipv4"`
	// EnableIPv6 is whether IPv6 addressing is enabled. If enabled, all endpoints are allocated an IPv6 address.
	EnableIPv6 bool `json:"enable-ipv6"`
	// LocalRouterIPv4 is the static link-local IPv4 address to be assigned to the Cilium router.
	LocalRouterIPv4 string `json:"local-router-ipv4"`
	// LocalRouterIPv6 is the static link-local IPv6 address to be assigned to the Cilium router.
	LocalRouterIPv6 string `json:"local-router-ipv6"`
	// FastStartNamespaces is a comma-separated list of namespaces for which fast start is enabled. Set to "@all" if enabled for all the namespaces.
	FastStartNamespaces string `json:"dpv2-fast-start-namespaces"`
}
