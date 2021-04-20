package option

// Add Google-specific options to this file.
const (
	// Define constants here. Do not delete this entry and comment.
	_ = 0

	// EnableEnhancedServices enables the Enhanced Services feature
	// offered by GKE 1N, go/gke-1n-dataplane-ug.
	EnableEnhancedServices = "enable-enhanced-services"

	// TrafficDirectorMesh is the name of the Traffic Director mesh used for Advanced Service Routing.
	TrafficDirectorMesh = "traffic-director-mesh"

	// EnableGoogleMultiNIC is the name of the option to enable gogole multi nic support.
	EnableGoogleMultiNIC = "enable-google-multi-nic"

	// EnableGoogleConfigOverrideName is the name for the option to enable
	// overriding Cilium configuration by reading from
	// cilium-config-emergency-override ConfigMap.
	EnableGoogleConfigOverrideName = "enable-google-config-override"

	// EnableNodeNetworkPolicyCRD enables google node network policy CRD.
	EnableNodeNetworkPolicyCRD = "enable-node-network-policy-crd"

	// AnnotateK8sNodeSubnet enables annotation of kubernetes nodes with subnet information.
	AnnotateK8sNodeSubnet = "annotate-k8s-node-subnet"

	// DisablePolicyEventCountMetric  disables the policy event count metric on this host.
	DisablePolicyEventCountMetric = "disable-policy-event-count-metric"

	// EnableFQDNNetworkPolicy enables google fqdn network policy
	EnableFQDNNetworkPolicy = "enable-fqdn-network-policy"

	// AllowIMDSAccessInHostNSOnly adds bpf logic that will block non-hostnetwork
	// pods from accessing IMDS at 169.254.169.254.
	AllowIMDSAccessInHostNSOnly = "allow-imds-access-in-hostns-only"

	// EnableGoogleMultiNICHaipin is the name of the option to enable gogole multi nic hairpin support.
	EnableGoogleMultiNICHairpin = "enable-google-multi-nic-hairpin"

	// DevicePrefixesToExclude excludes google-managed devices with the provided prefixes.
	DevicePrefixesToExclude = "device-prefixes-to-exclude"

	// PopulateGCENICInfo is the name of the option to populate GCE NIC information as node annotation.
	PopulateGCENICInfo = "populate-gce-nic-info"

	// EnableTrafficSteering enables google traffic steering for the host.
	EnableTrafficSteering = "enable-traffic-steering"
)
