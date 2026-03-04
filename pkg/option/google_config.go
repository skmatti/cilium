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

	// EnableGoogleMultiNICHostFirewall is the name of the option to enable google
	// multi NIC support for host firewall policies.
	EnableGoogleMultiNICHostFirewall = "enable-google-multi-nic-host-firewall"
	// GoogleMultiNICHostMapping is the name of the option to which maps
	// numeric identities to a multi nic host network name.
	GoogleMultiNICHostMapping = "google-multi-nic-host-mapping"

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

	// DisableIPv6Tunnel is the name of the option to disable tunnel for IPv6
	DisableIPv6Tunnel = "disable-ipv6-tunnel"

	// EnableAutoDirectRoutingIPv4Name is the name for the EnableAutoDirectRoutingIPv4 option.
	EnableAutoDirectRoutingIPv4Name = "auto-direct-node-routes-ipv4"

	// EnableAutoDirectRoutingIPv6Name is the name for the EnableAutoDirectRoutingIPv6 option.
	EnableAutoDirectRoutingIPv6Name = "auto-direct-node-routes-ipv6"

	// AllowIMDSAccessInHostNSOnly adds bpf logic that will block non-hostnetwork
	// pods from accessing IMDS at 169.254.169.254.
	AllowIMDSAccessInHostNSOnly = "allow-imds-access-in-hostns-only"
	// EnableGoogleIPOptionTracing is the name of the option to enable packet tracing
	// using IP options.
	EnableGoogleIPOptionTracing = "enable-ip-option-tracing"
	// EnableGoogleMultiNICHaipin is the name of the option to enable gogole multi nic hairpin support.
	EnableGoogleMultiNICHairpin = "enable-google-multi-nic-hairpin"

	// EnableGoogleNorthSouthIpOptionTracing is the name of the option to enable packet tracing
	// detagging for north bound traffic.
	EnableGoogleNorthSouthIpOptionTracing = "enable-north-south-ip-option-tracing"

	// DevicePrefixesToExclude excludes google-managed devices with the provided prefixes.
	DevicePrefixesToExclude = "device-prefixes-to-exclude"

	// EnableGooglePersistentIP is the name of the option to enable google persistent-ip support.
	EnableGooglePersistentIP = "enable-google-persistent-ip"

	// EnableTrafficSteering enables google traffic steering for the host.
	EnableTrafficSteering = "enable-traffic-steering"

	// EnableStrictEgressPolicyValidation enables egress traffic check for infra cluster.
	EnableStrictEgressPolicyValidation = "enable-strict-egress-policy-validation"

	// StrictEgressPolicyValidationAllowAccessLabels defines the "infra-access" label name,
	// which we will use to determine if a pod has permission to egress NAT.
	StrictEgressPolicyValidationAllowAccessLabels = "strict-egress-policy-validation-allow-access-labels"

	// StrictEgressPolicyValidationReconciliationTriggerInterval defines the minimal interval of triggering
	// strict egress policy validation reconciliation.
	StrictEgressPolicyValidationReconciliationTriggerInterval = "strict-egress-policy-validation-reconciliation-trigger-interval"

	// EnableFlatIPv4 is the name of the option to enable flat IP for IPv4
	EnableFlatIPv4 = "enable-flat-ipv4"

	// EnableGKEMultiTenancy is used to enable GKE Multi-tenancy mode.
	//
	// Ref. http://go/dpv2-with-gke-multi-tenancy
	//
	// NOTE: The flag name is deliberately obscured to "enable-multi-project" to
	// avoid directly revealing the GKE Multi-tenancy feature to all customers
	// during startup logs, even those not using it. This decision was made in
	// consultation with the wider GKE Multi-tenancy team.
	EnableGKEMultiTenancy = "enable-multi-project"

	// DisablePodToRemoteNodeTunneling disables tunneling for all traffic to the remote nodes.
	DisablePodToRemoteNodeTunneling = "disable-pod-to-remote-node-tunneling"

	// EnableGDCILB is the name of the option to enable google GDC-H ILB Support
	EnableGDCILB = "enable-gdc-ilb"

	// RegisterIPv4PodGateway is the option to register the Pod CIDR Gateway IP
	// (the first IP in the Pod CIDR) as a host identity. This allows kubelet
	// health-checks to be recognized as coming from the host.
	RegisterIPv4PodGateway = "register-ipv4-pod-gateway"

	// EnableGoogleMultiNICEgressNAT is the name of the option to enable egress nat policies for google multi NIC endpointpoints.
	EnableGoogleMultiNICEgressNAT = "enable-google-multi-nic-egress-nat"

	// GoogleRestrictK8sNPScopeToLocalCluster is the name of the option to restrict K8s NetworkPolicy scope to the local cluster
	GoogleRestrictK8sNPScopeToLocalCluster = "google-restrict-k8s-np-scope-to-local-cluster"

	// EndpointSystemLabels is the name of the endpoint system labels option.
	EndpointSystemLabels = "endpoint-system-labels"

	// Enable mTLS for metrics server
	AgentEnableMetricsServerTLS = "agent-enable-metrics-server-tls"

	// MetricsServerTLSCertFile specifies the path to the public key file for
	// the metrics server. The file must contain PEM encoded data.
	AgentMetricsServerTLSCertFile = "agent-metrics-server-tls-cert-file"

	// MetricsServerTLSKeyFile specifies the path to the private key file for
	// the metrics server. The file must contain PEM encoded data.
	AgentMetricsServerTLSKeyFile = "agent-metrics-server-tls-key-file"

	// MetricsServerTLSClientCAFiles specifies the path to one or more client
	// CA certificates to use for TLS with mutual authentication (mTLS) on the
	// metrics server. The files must contain PEM encoded data.
	AgentMetricsServerTLSClientCAFiles = "agent-metrics-server-tls-client-ca-files"

	// EnableGoogleBPFGeneve is the name of the option to enable Google BPF Geneve encapsulation.
	EnableGoogleBPFGeneve = "enable-google-bpf-geneve"

	// XDPMode sets the XDP mode.
	XDPMode = "xdp-mode"

	// XDPDevices is the name of the option to override XDP device list.
	XDPDevices = "xdp-devices"

	// EnableGoogleVPC is the name of the option to enable Google VPC.
	EnableGoogleVPC = "enable-google-vpc"

	// GoogleIPSecMode is the option to set Google IPSec mode. Possible values are "disabled" (default), "software", "hardware-offload".
	GoogleIPSecMode = "google-ipsec-mode"

	// DisableClusterIDValidation provides backward compatibility for a cilium-agent (v1.16+) that
	// is processing a remote cluster's node/service KV store entries managed by an older
	// clustermesh instance (v1.13). Newer clustermesh versions embed a cluster ID in the value of
	// each node/service entry, and the agent validates its presence. Older ClusterMesh versions do
	// not add this field, so we disable the validation on new cilium-agent clients. This should
	// only be used as a temporary measure during mixed-version upgrades.
	DisableClusterIDValidation = "disable-cluster-id-validation"

	// EnableEgressPolicyRemoteEndpointSelection is a feature flag that enables
	// egress policy to select endpoints from remote clusters.
	EnableEgressPolicyRemoteEndpointSelection = "enable-egress-policy-remote-endpoint-selection"

	// EnableGatewayIPFromAnnotation is a feature flag that enables using
	// gateway IP from CiliumEgressGatewayPolicy annotation
	EnableGatewayIPFromAnnotation = "enable-gateway-ip-from-annotation"

	// EgressGatewayPendingIdentityExpirySeconds is the number of seconds before the egressgateway
	// manager cleans up an endpoint with unlearned labels.
	EgressGatewayPendingIdentityExpirySeconds = "egress-gateway-pending-identity-expiry-seconds"

	// PerimeterEndpointNetwork is the name of the network the perimeter endpoints are connected to.
	PerimeterEndpointNetwork = "perimeter-endpoint-network"

	// EnableGooglePerimeterFeatures is a feature flag that enables using
	// perimeter cluster based egress nat and elb.
	EnableGooglePerimeterFeatures = "enable-google-perimeter-features"

	// PerimeterMapsGCIntervalSeconds is the name of the option to set the interval (in seconds)
	// between successive runs of the perimeter maps GC process.
	PerimeterMapsGCIntervalSeconds = "perimeter-maps-gc-interval-seconds"

	// RemoteClusterNamespacesToSkip specifies a list of namespaces in remote clusters to ignore when synchronizing
	// identities and IP-to-identity mappings via clustermesh.
	RemoteClusterNamespacesToSkip = "remote-cluster-namespaces-to-skip"

	// EnableExtendedIPProtocols controls whether traffic with extended IP protocols is supported in datapath
	EnableExtendedIPProtocols = "enable-extended-ip-protocols"

	// EnableServiceAliasing controls service aliasing behaviour in ClusterMesh.
	EnableServiceAliasing = "enable-service-aliasing"

	// ServiceAliasNameAnnotation specifies the service annotation which contains the alias name.
	ServiceAliasNameAnnotation = "service-alias-name-annotation"

	// ServiceAliasNamespace specifies the namespace to be used for service aliasing.
	ServiceAliasNamespace = "service-alias-namespace"

	// DisableRouteMTUOverheadName is the name of the DisableRouteMTUOverhead option
	DisableRouteMTUOverheadName = "disable-route-mtu-overhead"
)
