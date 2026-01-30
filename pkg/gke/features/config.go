package features

import (
	"fmt"

	"github.com/cilium/cilium/pkg/datapath/linux/config/defines"
	"github.com/cilium/cilium/pkg/gke/multinic/multinicconfig"
	googlectmapconst "github.com/cilium/cilium/pkg/maps/google_ctmap/consts"
	perimeterconst "github.com/cilium/cilium/pkg/maps/perimetermap/consts"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/hive/cell"
	"github.com/spf13/pflag"
)

const (
	// Define constants here. Do not delete this entry and comment.
	_ = 0
	// EnableLoadBalancerIPAM enables the LoadBalancer IPAM feature, and exposes the CiliumLoadBalancerIPPool CRD
	EnableLoadBalancerIPAM = "enable-lbipam"
	// EnableMultiPoolIPAM enables the multi-pool IPAM feature, and exposes the CiliumPodIPPool CRD
	EnableMultiPoolIPAM = "enable-multipool-ipam"
	// EnableCiliumNodeConfig enables the CiliumNodeConfig CRD
	EnableCiliumNodeConfig = "enable-cnc"
	// GoogleIPSecModeDisabled indicates the node-to-node encryption feature is disabled.
	GoogleIPSecModeDisabled = "disabled"
	// GoogleIPSecModeSoftware indicates the node-to-node encryption feature is in software mode.
	GoogleIPSecModeSoftware = "software"
)

// Used when config can't be injected by the Hive
var GlobalConfig = defaultConfig

var Cell = cell.Module(
	"features",
	"Features",

	cell.Config(defaultConfig),
	multinicconfig.Cell,
	cell.Provide(configure),
)

// Config struct used to gate OSS features that otherwise have no means to be disabled
type Config struct {
	// Add fields here. Do not delete this comment.
	// DisableIPv6Tunnel determines if IPv6 tunnel should be explicitly disabled. Currently Tunnel is enabled for both IP families by default.
	DisableIPv6Tunnel bool
	// EnableAutoDirectRoutingIPv4 enables installation of IPv4 direct routes to other nodes when available
	EnableAutoDirectRoutingIPv4 bool `mapstructure:"auto-direct-node-routes-ipv4"`
	// EnableAutoDirectRoutingIPv6 enables installation of IPv6 direct routes to other nodes when available
	EnableAutoDirectRoutingIPv6 bool `mapstructure:"auto-direct-node-routes-ipv6"`
	// EnableLoadBalancerIPAM enables the LB IPAM feature
	EnableLoadBalancerIPAM bool `mapstructure:"enable-lbipam"`
	// EnableMultiPoolIPAM enables the multi-pool IPAM feature
	EnableMultiPoolIPAM bool `mapstructure:"enable-multipool-ipam"`
	// EnableCiliumNodeConfig enables the CiliumNodeConfig CRD
	EnableCiliumNodeConfig bool `mapstructure:"enable-cnc"`

	// EnableGoogleConfigOverride enables overriding Cilium configuration by
	// reading from cilium-config-emergency-override ConfigMap.
	EnableGoogleConfigOverride bool
	// EnableGoogleMultiNICHairpin is a flag for google multi nic hairpin support, default is true.
	EnableGoogleMultiNICHairpin bool
	// DevicePrefixesToExclude excludes google-managed devices with the provided prefixes.
	DevicePrefixesToExclude []string
	// EnableGKEMultiTenancy is used to enable GKE Multi-tenancy mode.
	//
	// Ref. http://go/dpv2-with-gke-multi-tenancy
	EnableGKEMultiTenancy bool `mapstructure:"enable-multi-project"`
	// DisablePodToRemoteNodeTunneling disables tunneling for all traffic to the remote nodes.
	DisablePodToRemoteNodeTunneling bool `mapstructure:"disable-pod-to-remote-node-tunneling"`
	EnableGDCILB                    bool `mapstructure:"enable-gdc-ilb"`
	// EnableGoogleMultiNICEgressNAT is the option to enable egress NAT policies for multi NIC endpoints.
	EnableGoogleMultiNICEgressNAT bool

	// GoogleRestrictK8sNPScopeToLocalCluster is a flag to restrict K8s NetworkPolicy scope to the local cluster.
	GoogleRestrictK8sNPScopeToLocalCluster bool `mapstructure:"google-restrict-k8s-np-scope-to-local-cluster"`

	// EnableGoogleIPOptionTracing enables packet tracing using a trace ID in the
	// first Stream ID IP option. This feature ignores packets where the SID
	// option is not in the first 3 IP options. The default is false.
	EnableGoogleIPOptionTracing bool `mapstructure:"enable-ip-option-tracing"`
	// EnableGoogleNorthSouthIpOptionTracing enables a Google-specific packet tracing
	// detagging for north bound traffic (packets leaving the cluster).
	// EnableGoogleIPOptionTracing flag should be enabled for EnableGoogleNorthSouthIpOptionTracing to
	// start packet detagging for north bound traffic.
	EnableGoogleNorthSouthIpOptionTracing bool `mapstructure:"enable-north-south-ip-option-tracing"`
	// EnableGoogleBPFGeneve determines whether to encap and decap traffic by BPF Geneve. Default is false, which means
	// encap and decap is done by kernel.
	EnableGoogleBPFGeneve bool
	// Sets the XDP mode of each node.
	XDPMode string
	// XDPDevices specify a list of interfaces where we want to install XDP program on. By default, XDP programs will
	// be installed on all devices detected by Cilium. When this is not empty, XDP program will only be installed on these
	// interfaces.
	XDPDevices []string `mapstructure:"xdp-devices"`
	// EnableGoogleVPC is the option to enable Google VPC mode.
	EnableGoogleVPC bool
	// GoogleIPSecMode is the option to set Google IPSec mode. Possible values are "disabled" (default), "software"
	// Use string instead of bool since we may support more modes in the future. e.g. "hardware-offload".
	GoogleIPSecMode string
	// EgressGatewayPendingIdentityExpirySeconds specifies the number of seconds before the manager cleans up an endpoint with unlearned labels.
	EgressGatewayPendingIdentityExpirySeconds int `mapstructure:"egress-gateway-pending-identity-expiry-seconds"`
	// DisableClusterIDValidation provides backward compatibility for a cilium-agent (v1.16+) that
	// is processing a remote cluster's node/service KV store entries managed by an older
	// clustermesh instance (v1.13). Newer clustermesh versions embed a cluster ID in the value of
	// each node/service entry, and the agent validates its presence. Older ClusterMesh versions do
	// not add this field, so we disable the validation on new cilium-agent clients. This should
	// only be used as a temporary measure during mixed-version upgrades.
	DisableClusterIDValidation bool
	// EnableEgressPolicyRemoteEndpointSelection is a feature flag that enables
	// egress policy to select endpoints from remote clusters.
	EnableEgressPolicyRemoteEndpointSelection bool `mapstructure:"enable-egress-policy-remote-endpoint-selection"`
	// EnableGatewayIPFromAnnotation is a feature flag that enables using
	// gateway IP from CiliumEgressGatewayPolicy annotation
	EnableGatewayIPFromAnnotation bool `mapstructure:"enable-gateway-ip-from-annotation"`
	// PerimeterEndpointNetwork is the name of the network the perimeter endpoints are connected to.
	PerimeterEndpointNetwork string `mapstructure:"perimeter-endpoint-network"`
	// EnableGooglePerimeterFeatures is a feature flag that enables using
	// perimeter cluster based egress nat and elb.
	EnableGooglePerimeterFeatures bool `mapstructure:"enable-google-perimeter-features"`
	// PerimeterMapsGCIntervalSeconds specifies the number of seconds between successive runs of the perimeter maps GC process.
	// This value is configurable via the "perimeter-maps-gc-interval-seconds" setting.
	PerimeterMapsGCIntervalSeconds int `mapstructure:"perimeter-maps-gc-interval-seconds"`
	// EnableExtendedIPProtocols controls whether traffic with extended IP protocols is supported in datapath
	EnableExtendedIPProtocols bool `mapstructure:"enable-extended-ip-protocols"`
}

var defaultConfig = Config{
	// Add fields here. Do not delete this comment.
	DisableIPv6Tunnel:           false,
	EnableAutoDirectRoutingIPv4: false,
	EnableAutoDirectRoutingIPv6: false,

	EnableGoogleConfigOverride:  false,
	EnableGoogleMultiNICHairpin: false,
	DevicePrefixesToExclude:     []string{},
	EnableMultiPoolIPAM:         false,
	EnableGKEMultiTenancy:       false,

	DisablePodToRemoteNodeTunneling:        false,
	EnableGDCILB:                           false,
	EnableGoogleMultiNICEgressNAT:          false,
	GoogleRestrictK8sNPScopeToLocalCluster: false,

	// EnableGoogleIPOptionTracing is disabled by default.
	EnableGoogleIPOptionTracing:               false,
	EnableGoogleNorthSouthIpOptionTracing:     false,
	EnableGoogleBPFGeneve:                     false,
	XDPMode:                                   option.XDPModeDisabled,
	XDPDevices:                                []string{},
	EnableGoogleVPC:                           false,
	GoogleIPSecMode:                           GoogleIPSecModeDisabled,
	EgressGatewayPendingIdentityExpirySeconds: 300,
	DisableClusterIDValidation:                false,
	// TODO: (b/439930952) move these perimeter elb flags into a cell
	EnableEgressPolicyRemoteEndpointSelection: false,
	EnableGatewayIPFromAnnotation:             false,
	PerimeterEndpointNetwork:                  "g-perimeter-network",
	EnableGooglePerimeterFeatures:             false,
	PerimeterMapsGCIntervalSeconds:            1800,
	EnableExtendedIPProtocols:                 false,
}

func (cfg Config) Flags(flags *pflag.FlagSet) {
	// Add flags here. Do not delete this comment.
	flags.Bool(option.DisableIPv6Tunnel, defaultConfig.DisableIPv6Tunnel, "Disable tunnel for IPv6")
	flags.MarkHidden(option.DisableIPv6Tunnel)

	flags.Bool(option.EnableAutoDirectRoutingIPv4Name, defaultConfig.EnableAutoDirectRoutingIPv4, "Enable installation of IPv4 direct routes to other nodes when available")
	flags.MarkHidden(option.EnableAutoDirectRoutingIPv4Name)

	flags.Bool(option.EnableAutoDirectRoutingIPv6Name, defaultConfig.EnableAutoDirectRoutingIPv6, "Enable installation of IPv6 direct routes to other nodes when available")
	flags.MarkHidden(option.EnableAutoDirectRoutingIPv6Name)

	flags.Bool(EnableLoadBalancerIPAM, defaultConfig.EnableLoadBalancerIPAM, "Enable LoadBalancer IP Address Management (IPAM)")
	flags.MarkHidden(EnableLoadBalancerIPAM)

	flags.Bool(EnableMultiPoolIPAM, defaultConfig.EnableMultiPoolIPAM, "Enable Multi-Pool IPAM")
	flags.MarkHidden(EnableMultiPoolIPAM)

	flags.Bool(EnableCiliumNodeConfig, defaultConfig.EnableCiliumNodeConfig, "Enable CiliumNodeConfig")
	flags.MarkHidden(EnableCiliumNodeConfig)

	flags.Bool(option.EnableGoogleConfigOverrideName, defaultConfig.EnableGoogleConfigOverride, `Enable overriding Cilium configuration by reading from cilium-config-emergency-override ConfigMap`)
	flags.MarkHidden(option.EnableGoogleConfigOverrideName)

	flags.Bool(option.EnableGoogleMultiNICHairpin, defaultConfig.EnableGoogleMultiNICHairpin, "Enable google multi NIC local hairpin for local L2 broadcast")
	flags.MarkHidden(option.EnableGoogleMultiNICHairpin)

	flags.StringSlice(option.DevicePrefixesToExclude, []string{}, "(Google-internal) List of prefixes of devices for Cilium to exclude")
	flags.MarkHidden(option.DevicePrefixesToExclude)

	// The lack of clarity in the description of this flag is deliberate. Aim is
	// to avoid directly revealing the GKE Multi-tenancy feature to all
	// customers during startup logs, even those not using it. This decision was
	// made in consultation with the wider GKE Multi-tenancy team.
	flags.Bool(option.EnableGKEMultiTenancy, defaultConfig.EnableGKEMultiTenancy, "Enable multi-project support for Cilium.")
	flags.MarkHidden(option.EnableGKEMultiTenancy)

	flags.Bool(option.DisablePodToRemoteNodeTunneling, defaultConfig.DisablePodToRemoteNodeTunneling, "Disable tunneling for traffic from a pod to the remote nodes")
	flags.MarkHidden(option.DisablePodToRemoteNodeTunneling)

	flags.Bool(option.EnableGDCILB, defaultConfig.EnableGDCILB, "Enable google GDC-H ILB Support")
	flags.MarkHidden(option.EnableGDCILB)

	flags.Bool(option.EnableGoogleMultiNICEgressNAT, defaultConfig.EnableGoogleMultiNICEgressNAT, "Enable Egress NAT policies for Google multi NIC endpoints")
	flags.MarkHidden(option.EnableGoogleMultiNICEgressNAT)

	flags.Bool(option.GoogleRestrictK8sNPScopeToLocalCluster, defaultConfig.GoogleRestrictK8sNPScopeToLocalCluster, "Restrict K8s NetworkPolicy scope to the local cluster")
	flags.MarkHidden(option.GoogleRestrictK8sNPScopeToLocalCluster)

	flags.Bool(option.EnableGoogleIPOptionTracing, cfg.EnableGoogleIPOptionTracing, "Enables packet tracing using a trace ID in the IP option header")
	flags.MarkHidden(option.EnableGoogleIPOptionTracing)

	flags.Bool(option.EnableGoogleNorthSouthIpOptionTracing, defaultConfig.EnableGoogleNorthSouthIpOptionTracing, "Enable Google North-South IP option detagging mode")
	flags.MarkHidden(option.EnableGoogleNorthSouthIpOptionTracing)

	flags.Bool(option.EnableGoogleBPFGeneve, cfg.EnableGoogleBPFGeneve, "Enable Google VPC mode")
	flags.MarkHidden(option.EnableGoogleBPFGeneve)

	flags.String(option.XDPMode, cfg.XDPMode, "Set XDP mode")
	flags.MarkHidden(option.XDPMode)

	flags.StringSlice(option.XDPDevices, cfg.XDPDevices, "Override XDP device list")
	flags.MarkHidden(option.XDPDevices)

	flags.Bool(option.EnableGoogleVPC, cfg.EnableGoogleVPC, "Enable Google VPC mode")
	flags.MarkHidden(option.EnableGoogleVPC)

	flags.String(option.GoogleIPSecMode, cfg.GoogleIPSecMode,
		fmt.Sprintf("GoogleIPSecMode is the option to set Google IPSec mode. Possible values are %v. Default value is %q",
			[]string{GoogleIPSecModeDisabled, GoogleIPSecModeSoftware}, cfg.GoogleIPSecMode))
	flags.MarkHidden(option.GoogleIPSecMode)

	flags.Int(option.EgressGatewayPendingIdentityExpirySeconds,
		defaultConfig.EgressGatewayPendingIdentityExpirySeconds, "Set the duration before which pending egress gateway endpoints are cleaned up")
	flags.MarkHidden(option.EgressGatewayPendingIdentityExpirySeconds)

	flags.Bool(option.DisableClusterIDValidation, cfg.DisableClusterIDValidation, "Disable remote cluster cluster ID validation for node/service kvstore entries")
	flags.MarkHidden(option.DisableClusterIDValidation)

	flags.Bool(option.EnableEgressPolicyRemoteEndpointSelection, false, "Enable egress policy to select endpoints from remote clusters")
	flags.MarkHidden(option.EnableEgressPolicyRemoteEndpointSelection)

	flags.Bool(option.EnableGatewayIPFromAnnotation, false, "Enable using gateway IP from CiliumEgressGatewayPolicy annotation")
	flags.MarkHidden(option.EnableGatewayIPFromAnnotation)

	flags.String(option.PerimeterEndpointNetwork, defaultConfig.PerimeterEndpointNetwork, "Name of the network that the perimeter networks belong to.")
	flags.MarkHidden(option.PerimeterEndpointNetwork)

	flags.Bool(option.EnableGooglePerimeterFeatures, defaultConfig.EnableGooglePerimeterFeatures, "Enable perimeter cluster networking features.")
	flags.MarkHidden(option.EnableGooglePerimeterFeatures)

	flags.Int(option.PerimeterMapsGCIntervalSeconds, defaultConfig.PerimeterMapsGCIntervalSeconds, "Set the interval in seconds between successive runs of the perimeter maps GC process")
	flags.MarkHidden(option.PerimeterMapsGCIntervalSeconds)

	flags.Bool(option.EnableExtendedIPProtocols, false, "Enable traffic with extended IP protocols in datapath")
	flags.MarkHidden(option.EnableExtendedIPProtocols)
}

func configure(cfg Config, daemonCfg *option.DaemonConfig) (out struct {
	cell.Out

	defines.NodeOut
}, err error) {
	GlobalConfig = cfg

	out.NodeDefines = make(defines.Map)
	if cfg.EnableGoogleIPOptionTracing {
		out.NodeDefines["ENABLE_GOOGLE_IP_OPTION_TRACING"] = "1"
	}

	if cfg.EnableGoogleNorthSouthIpOptionTracing {
		if !cfg.EnableGoogleIPOptionTracing {
			return out, fmt.Errorf("enabling North South traffic detagging requires Google IP Options Tracing to be enabled")
		}
		out.NodeDefines["ENABLE_GOOGLE_NORTH_SOUTH_IP_OPTION_TRACING"] = "1"
	}

	if cfg.EnableGoogleBPFGeneve {
		out.NodeDefines["ENABLE_GOOGLE_GENEVE"] = "1"
	}

	if cfg.EnableGoogleVPC {
		if !cfg.EnableGoogleBPFGeneve || !daemonCfg.TunnelingEnabled() {
			return out, fmt.Errorf("feature Google VPC requires %s set to 'true' (currently %t) and tunnel enabled (currently %t)",
				option.EnableGoogleBPFGeneve, cfg.EnableGoogleBPFGeneve, daemonCfg.TunnelingEnabled())
		}
		out.NodeDefines["ENABLE_GOOGLE_VPC"] = "1"
	}

	switch cfg.GoogleIPSecMode {
	case GoogleIPSecModeSoftware:
		out.NodeDefines["GOOGLE_IPSEC_MODE"] = "1"
	case GoogleIPSecModeDisabled:
		fallthrough
	default:
		out.NodeDefines["GOOGLE_IPSEC_MODE"] = "0"
	}

	if cfg.EnableGatewayIPFromAnnotation {
		if !(daemonCfg.EnableIPv4EgressGateway && cfg.EnableGoogleVPC) {
			return out, fmt.Errorf("Egress Gateway Redirection requires Google VPC and Gateway IP From Annotation enabled")
		}
		out.NodeDefines["ENABLE_EGRESS_GATEWAY_REDIRECT"] = "1"
		out.NodeDefines["GOOGLE_REDIRECT_EP_IP_V4_MAP"] = perimeterconst.RedirectEPIPMap4Name
		out.NodeDefines["GOOGLE_REDIRECT_EP_ID_V4_MAP"] = perimeterconst.RedirectEPIDMap4Name
	}

	if cfg.EnableGooglePerimeterFeatures {
		out.NodeDefines["GOOGLE_PERIMETER_FEATURES"] = "1"
	}

	out.NodeDefines["GOOGLE_CT_MAP_V4"] = googlectmapconst.GoogleCtMapName

	if cfg.EnableExtendedIPProtocols {
		out.NodeDefines["ENABLE_EXTENDED_IP_PROTOCOLS"] = "1"
	}
	return
}
