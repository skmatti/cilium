package option

// Add Google-specific options to this file.
const (
	// EnableNodeNetworkPolicyCRD enables google node network policy CRD.
	EnableNodeNetworkPolicyCRD = "enable-node-network-policy-crd"

	// AnnotateK8sNodeSubnet enables annotation of kubernetes nodes with subnet information.
	AnnotateK8sNodeSubnet = "annotate-k8s-node-subnet"

	// EnableGDCILB is the name of the option to enable google GDC-H ILB Support
	EnableGDCILB = "enable-gdc-ilb"

	// AllowIMDSAccessInHostNSOnly adds bpf logic that will block non-hostnetwork
	// pods from accessing IMDS at 169.254.169.254.
	AllowIMDSAccessInHostNSOnly = "allow-imds-access-in-hostns-only"

	// EnableFlatIPv4 is the name of the option to enable flat IP for IPv4
	EnableFlatIPv4 = "enable-flat-ipv4"

	// DisableIPv6Tunnel is the name of the option to disable tunnel for IPv6
	DisableIPv6Tunnel = "disable-ipv6-tunnel"

	// EnableTrafficSteering enables google traffic steering for the host.
	EnableTrafficSteering = "enable-traffic-steering"

	// EnableGoogleMultiNIC is the name of the option to enable gogole multi nic support.
	EnableGoogleMultiNIC = "enable-google-multi-nic"

	// EnableGoogleServiceSteering is the name of the option to enable google service steering support.
	EnableGoogleServiceSteering = "enable-google-service-steering"

	// EnableFQDNNetworkPolicy enables google fqdn network policy
	EnableFQDNNetworkPolicy = "enable-fqdn-network-policy"

	// EnableRedirectService enables google redirect service for the host
	EnableRedirectService = "enable-redirect-service"

	// EnableGNG internal flag to enable GNG's eBPF code paths. This should be
	// replaced with the ServiceChaining enablement.
	EnableGNG = "enable-gng"

	// PopulateGCENICInfo is the name of the option to populate GCE NIC information as node annotation.
	PopulateGCENICInfo = "populate-gce-nic-info"

	// DisablePodToRemoteNodeTunneling disables tunneling for all traffic to the remote nodes.
	DisablePodToRemoteNodeTunneling = "disable-pod-to-remote-node-tunneling"

	// DevicePrefixesToExclude excludes google-managed devices with the provided prefixes.
	DevicePrefixesToExclude = "device-prefixes-to-exclude"
)
