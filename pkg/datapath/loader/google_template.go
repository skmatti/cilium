package loader

import (
	"github.com/cilium/cilium/pkg/datapath"
	multinicep "github.com/cilium/cilium/pkg/gke/multinic/endpoint"
	"github.com/cilium/cilium/pkg/mac"
)

const (
	templatePodStackRedirectIfIndex = int(0xdeadbeef)
	templateParentDevIfIndex        = templatePodStackRedirectIfIndex
	templateNetworkID               = ^uint32(0)
)

// GetPodStackRedirectIfindex returns a filler podStackRedirectIfindex
// compile-time/which/will be later substituted in the ELF.
func (t *templateCfg) GetPodStackRedirectIfindex() int {
	return templatePodStackRedirectIfIndex
}

// GetParentDevIndex returns a filler parent dev index
// compile-time/which/will be later substituted in the ELF.
func (t *templateCfg) GetParentDevIndex() int {
	return templateParentDevIfIndex
}

// GetNetworkID returns a filler for network id
// compile-time/which/will be later substituted in the ELF.
func (t *templateCfg) GetNetworkID() uint32 {
	return templateNetworkID
}

// GetParentDevMac returns a filler parent dev mac address
// compile-time/which/will be later substituted in the ELF.
func (t *templateCfg) GetParentDevMac() mac.MAC {
	return templateMAC
}

// multiNicElfVariableSubstitutions fills in Elf substitutions in the template,
// pertaining to Multi-nic endpoints.
func multiNicElfVariableSubstitutions(ep datapath.Endpoint,
	result map[string]uint32) {
	if !ep.IsMultiNIC() {
		return
	}

	result["POD_STACK_REDIRECT_IFINDEX"] =
		uint32(ep.GetPodStackRedirectIfindex())
	result["PARENT_DEV_IFINDEX"] = uint32(ep.GetParentDevIndex())

	if ep.GetDeviceTypeIndex() == multinicep.EndpointDeviceIndexMultinicVETH {
		// For L3 multinic endpoints only
		result["NETWORK_ID"] = ep.GetNetworkID()
		macAddr := ep.GetParentDevMac()
		result["PARENT_DEV_MAC_1"] = sliceToBe32(macAddr[0:4])
		result["PARENT_DEV_MAC_2"] = uint32(sliceToBe16(macAddr[4:6]))
	}
}
