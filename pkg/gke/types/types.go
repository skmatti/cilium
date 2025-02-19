package types

import "k8s.io/apimachinery/pkg/types"

type IPAM struct {
	// Type is the IPAM plugin to be used.
	Type string `json:"type"`
	// Ranges is the list of subnet ranges to be used for IP address allocation.
	Ranges [][]*SubnetRange `json:"ranges"`
	// Routes is the list of routes to be added to the interface.
	Routes []Route `json:"routes"`
	// DataDir is the directory where IPAM data is stored.
	DataDir string `json:"dataDir"`
}

type SubnetRange struct {
	// Subnet is the subnet range to be used for IP address allocation.
	Subnet string `json:"subnet"`
}

type Route struct {
	// Dst is the destination IP address or subnet.
	Dst string `json:"dst"`
}

type Network struct {
	// CNIVersion is the CNI version to be used.
	CNIVersion string `json:"cniVersion"`
	// TYPE is the CNI plugin type to be used.
	Type string `json:"type"`
	// Name is the name of the network.
	Name string `json:"name"`
	// UID is the UID of the network object.
	UID types.UID `json:"uid,omitempty"`
	// Interface is the name of the interface on the host.
	Interface string `json:"interface,omitempty"`
	// IPAM is the IPAM configuration for the network.
	IPAM IPAM `json:"ipam"`
}

type RuntimeConfig struct {
	// PodAnnotations is the pod annotations added to the pod.
	PodAnnotations *PodAnnotations `json:"io.kubernetes.cri.pod-annotations,omitempty"`
}

type PodAnnotations struct {
	// KubernetesIoConfigSeen  is the annotation to indicate that the configuration has been seen by the kubelet for the first time.
	KubernetesIOConfigSeen string `json:"kubernetes.io/config.seen,omitempty"`
	// KubernetesIoConfigSource is the annotation to indicate the source of the configuration.
	KubernetesIOConfigSource string `json:"kubernetes.io/config.source,omitempty"`
	// NetworkingGKEIODefaultInterface is the default interface for the pod.
	NetworkingGKEIODefaultInterface string `json:"networking.gke.io/default-interface,omitempty"`
	// NetworkingGKEIOInterfaces is the list of additional network interfaces and their corresponding network names.
	NetworkingGKEIOInterfaces string `json:"networking.gke.io/interfaces,omitempty"`
}

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
	// Networks is the list of networks that the CNI plugin should configure for additional interfaces.
	Networks []Network `json:"networks,omitempty"`
}

type CNIConfig struct {
	// CNIVersion is the CNI version to be used.
	CNIVersion string `json:"cniVersion"`
	// Type is the CNI plugin type to be used.
	Type string `json:"type"`
	// GCP is the GCP specific CNI network configuration.
	GCP GCPSpec `json:"gcp"`
	// RuntimeConfig is the runtime configuration for the CNI plugin.
	RuntimeConfig RuntimeConfig `json:"runtimeConfig"`
}
