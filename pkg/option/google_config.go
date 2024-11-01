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

	// EnableNodeNetworkPolicyCRD enables google node network policy CRD.
	EnableNodeNetworkPolicyCRD = "enable-node-network-policy-crd"
)
