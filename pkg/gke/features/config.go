package features

import (
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
)

var (
	// Used when config can't be injected by the Hive
	GlobalConfig = defaultConfig
)

var Cell = cell.Module(
	"features",
	"Features",

	cell.Config(defaultConfig),
	cell.Invoke(func(config Config) {
		GlobalConfig = config
	}),
)

// Config struct used to gate OSS features that otherwise have no means to be disabled
type Config struct {
	// Add fields here. Do not delete this comment.
	// EnableLoadBalancerIPAM enables the LB IPAM feature
	EnableLoadBalancerIPAM bool `mapstructure:"enable-lbipam"`
	// EnableMultiPoolIPAM enables the multi-pool IPAM feature
	EnableMultiPoolIPAM bool `mapstructure:"enable-multipool-ipam"`
	// EnableCiliumNodeConfig enables the CiliumNodeConfig CRD
	EnableCiliumNodeConfig bool `mapstructure:"enable-cnc"`
	// EnableGoogleMultiNIC enables multi-nic support
	EnableGoogleMultiNIC bool `mapstructure:"enable-google-multi-nic"`

	// EnableGoogleMultiNICHostFirewall enables multi-nic host firewall support
	EnableGoogleMultiNICHostFirewall bool              `mapstructure:"enable-google-multi-nic-host-firewall"`
	GoogleMultiNICHostMapping        map[string]string `mapstructure:"google-multi-nic-host-mapping"`

	// EnableGoogleConfigOverride enables overriding Cilium configuration by
	// reading from cilium-config-emergency-override ConfigMap.
	EnableGoogleConfigOverride bool
	// EnableGoogleMultiNICHairpin is a flag for google multi nic hairpin support, default is true.
	EnableGoogleMultiNICHairpin bool
	// DevicePrefixesToExclude excludes google-managed devices with the provided prefixes.
	DevicePrefixesToExclude []string
	PopulateGCENICInfo      bool
	// EnableGKEMultiTenancy is used to enable GKE Multi-tenancy mode.
	//
	// Ref. http://go/dpv2-with-gke-multi-tenancy
	EnableGKEMultiTenancy bool `mapstructure:"enable-multi-project"`
	// DisablePodToRemoteNodeTunneling disables tunneling for all traffic to the remote nodes.
	DisablePodToRemoteNodeTunneling bool `mapstructure:"disable-pod-to-remote-node-tunneling"`
}

var defaultConfig = Config{
	// Add fields here. Do not delete this comment.
	EnableGoogleMultiNIC: false,

	EnableGoogleMultiNICHostFirewall: false,
	GoogleMultiNICHostMapping:        make(map[string]string),

	EnableGoogleConfigOverride:  false,
	EnableGoogleMultiNICHairpin: false,
	DevicePrefixesToExclude:     []string{},
	PopulateGCENICInfo:          false,
	EnableMultiPoolIPAM:         false,
	EnableGKEMultiTenancy:       false,

	DisablePodToRemoteNodeTunneling: false,
}

func (cfg Config) Flags(flags *pflag.FlagSet) {
	// Add flags here. Do not delete this comment.
	flags.Bool(EnableLoadBalancerIPAM, defaultConfig.EnableLoadBalancerIPAM, "Enable LoadBalancer IP Address Management (IPAM)")
	flags.MarkHidden(EnableLoadBalancerIPAM)

	flags.Bool(EnableMultiPoolIPAM, defaultConfig.EnableMultiPoolIPAM, "Enable Multi-Pool IPAM")
	flags.MarkHidden(EnableMultiPoolIPAM)

	flags.Bool(EnableCiliumNodeConfig, defaultConfig.EnableCiliumNodeConfig, "Enable CiliumNodeConfig")
	flags.MarkHidden(EnableCiliumNodeConfig)
	flags.Bool(option.EnableGoogleMultiNIC, defaultConfig.EnableGoogleMultiNIC, "Enable google multi NIC support")
	flags.MarkHidden(option.EnableGoogleMultiNIC)

	flags.Bool(option.EnableGoogleMultiNICHostFirewall, defaultConfig.EnableGoogleMultiNICHostFirewall, "Enable google multi NIC local hairpin for local L2 broadcast")
	flags.MarkHidden(option.EnableGoogleMultiNICHostFirewall)
	flags.Var(option.NewNamedMapOptions(option.GoogleMultiNICHostMapping, &defaultConfig.GoogleMultiNICHostMapping, nil),
		option.GoogleMultiNICHostMapping, "Key-value pairs of numeric identity (must be in range [128, 255]) and network object name, e.g. `128=node-network1` or `140=node-network2,142=node-network3`")
	flags.MarkHidden(option.GoogleMultiNICHostMapping)

	flags.Bool(option.EnableGoogleConfigOverrideName, defaultConfig.EnableGoogleConfigOverride, `Enable overriding Cilium configuration by reading from cilium-config-emergency-override ConfigMap`)
	flags.MarkHidden(option.EnableGoogleConfigOverrideName)

	flags.Bool(option.EnableGoogleMultiNICHairpin, defaultConfig.EnableGoogleMultiNICHairpin, "Enable google multi NIC local hairpin for local L2 broadcast")
	flags.MarkHidden(option.EnableGoogleMultiNICHairpin)

	flags.StringSlice(option.DevicePrefixesToExclude, []string{}, "(Google-internal) List of prefixes of devices for Cilium to exclude")
	flags.MarkHidden(option.DevicePrefixesToExclude)

	flags.Bool(option.PopulateGCENICInfo, defaultConfig.PopulateGCENICInfo, "Populate GCE NIC information as node annotation.")
	flags.MarkHidden(option.PopulateGCENICInfo)

	// The lack of clarity in the description of this flag is deliberate. Aim is
	// to avoid directly revealing the GKE Multi-tenancy feature to all
	// customers during startup logs, even those not using it. This decision was
	// made in consultation with the wider GKE Multi-tenancy team.
	flags.Bool(option.EnableGKEMultiTenancy, defaultConfig.EnableGKEMultiTenancy, "Enable multi-project support for Cilium.")
	flags.MarkHidden(option.EnableGKEMultiTenancy)

	flags.Bool(option.DisablePodToRemoteNodeTunneling, defaultConfig.DisablePodToRemoteNodeTunneling, "Disable tunneling for traffic from a pod to the remote nodes")
	flags.MarkHidden(option.DisablePodToRemoteNodeTunneling)
}
