package loader

import (
	"github.com/cilium/cilium/pkg/datapath"
	multinicep "github.com/cilium/cilium/pkg/gke/multinic/endpoint"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/mac"
	"github.com/vishvananda/netlink"
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

// GetParentDevIndex returns a filler at compile-time, which will be later substituted in the ELF.
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

func mtuOfMultiNICEndpoint(ep datapath.Endpoint) uint32 {
	var link netlink.Link
	var err error
	scopedLog := log.WithField(logfields.EndpointID, ep.GetID())

	// The design for L3 network in ABM is not clear yet.
	// For now, assume the MTU is the same as parent device as in GKE.
	link, err = netlink.LinkByIndex(ep.GetParentDevIndex())
	if err != nil {
		// We don't have handle to return error but if it's happening, the endpoint is for sure collapsing.
		scopedLog.WithError(err).Errorf("failed to find parent device with index %d", ep.GetParentDevIndex())
		return 0
	}

	return uint32(link.Attrs().MTU)
}

// googleElfVariableSubstitutions fills in Elf substitutions in the template specifically for google.
func googleElfVariableSubstitutions(ep datapath.Endpoint,
	result map[string]uint32) {
	if !ep.IsMultiNIC() {
		return
	}
	result["MULTI_NIC_ENDPOINT_MTU"] = mtuOfMultiNICEndpoint(ep)
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
