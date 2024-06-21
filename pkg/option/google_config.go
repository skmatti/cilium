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

	// EnableGoogleIPOptionTracing is the name of the option to enable packet tracing
	// using IP options.
	EnableGoogleIPOptionTracing = "enable-ip-option-tracing"

	// EnableGoogleMultiNICHaipin is the name of the option to enable gogole multi nic hairpin support.
	EnableGoogleMultiNICHairpin = "enable-google-multi-nic-hairpin"

	// EnableGoogleMultiNICHostFirewall is the name of the option to enable google
	// multi NIC support for host firewall policies.
	EnableGoogleMultiNICHostFirewall = "enable-google-multi-nic-host-firewall"

	// GoogleMultiNICHostMapping is the name of the option to which maps
	// numeric identities to a multi nic host network name.
	GoogleMultiNICHostMapping = "google-multi-nic-host-mapping"

	// EnableTunnelFreeEgress enables tunnel-free egress NAT.
	// The option is ignored unless `enable-flat-ipv4` is true.
	EnableTunnelFreeEgress = "enable-tunnel-free-egress"

	// EnableGoogleServiceSteering is the name of the option to enable google service steering support.
	EnableGoogleServiceSteering = "enable-google-service-steering"

	// EnableGooglePersistentIP is the name of the option to enable google persistent-ip support.
	EnableGooglePersistentIP = "enable-google-persistent-ip"

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

	// K8sInterfaceOnly instructs Cilium to attach bpf_host programs only to the
	// interface with the k8s IP.
	K8sInterfaceOnly = "k8s-interface-only"

	// DevicePrefixesToExclude excludes google-managed devices with the provided prefixes.
	DevicePrefixesToExclude = "device-prefixes-to-exclude"

	// EnableLoadBalancerIPAM enables the LoadBalancer IPAM feature, and exposes the CiliumLoadBalancerIPPool CRD
	EnableLoadBalancerIPAM = "enable-lbipam"

	// EnableCiliumNodeConfig enables the CiliumNodeConfig CRD
	EnableCiliumNodeConfig = "enable-cnc"

	// ClustermeshNamespaceLabels configures a list of labels to limit clustermesh.
	// Clustermesh will only distribute information from namespaces that have one
	// of these labels.
	ClustermeshNamespaceLabels = "clustermesh-namespace-labels"

	// EnableHubbleCorrelatePolicies enables policy correlation for hubble flows.
	EnableHubbleCorrelatePolicies = "enable-hubble-correlate-policies"

	// DisablePolicyEventCountMetric  disables the policy event count metric on this host.
	DisablePolicyEventCountMetric = "disable-policy-event-count-metric"

	// (Deprecated) DisableCiliumNetworkPolicyCRDName is the name of the option to disable
	// use of the CNP and CCNP CRD
	DisableNetworkPolicyCRDName = "disable-network-policy-crd"

	// EnableCiliumNetworkPolicyName is the name of the option to enable
	// use of the CNP CRD
	EnableCiliumNetworkPolicyName = "enable-cilium-network-policy"

	// EnableCiliumCluterWideNetworkPolicyName is the name of the option to enable
	// use of the CCNP CRD
	EnableCiliumClusterWideNetworkPolicyName = "enable-cilium-clusterwide-network-policy"

	// EnableAutoDirectRoutingIPv4Name is the name for the EnableAutoDirectRoutingIPv4 option.
	EnableAutoDirectRoutingIPv4Name = "auto-direct-node-routes-ipv4"

	// EnableAutoDirectRoutingIPv6Name is the name for the EnableAutoDirectRoutingIPv6 option.
	EnableAutoDirectRoutingIPv6Name = "auto-direct-node-routes-ipv6"

	// AllowDisableSourceIPValidation is the name of the option to allow disabling source IP validation for multi-nic endpoints.
	AllowDisableSourceIPValidation = "allow-disable-source-ip-validation"

	// AllowDisableSourceMACValidation is the name of the option to allow disabling source MAC validation for multi-nic endpoints.
	AllowDisableSourceMACValidation = "allow-disable-source-mac-validation"

	// EnableGoogleVPC is the name of the option to enable Google VPC.
	EnableGoogleVPC = "enable-google-vpc"
)

func (c *DaemonConfig) SyncPredicate() func(string) bool {
	return nil
}
