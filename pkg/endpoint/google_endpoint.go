package endpoint

import (
	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/maps/localredirect"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/types"
)

// EndpointDeviceType is an enumeration for possible device types of an endpoint.
type EndpointDeviceType string

const (
	// EndpointDeviceVETH is a VETH device, which is the default type for an endpoint.
	// Keeping it empty to be backwards compatible.
	EndpointDeviceVETH = ""
	// EndpointDeviceMACVTAP is a MACVTAP device.
	EndpointDeviceMACVTAP = "macvtap"
	// EndpointDeviceMACVLAN is a MACVLAN device.
	EndpointDeviceMACVLAN = "macvlan"

	// MacvtapMapName specifies the tail call map for EP on both egress and ingress used with macvtap.
	MacvtapMapName = "cilium_multinic_"
)

// IsMultiNIC returns if the endpoint is a non veth endpoint.
func (e *Endpoint) IsMultiNIC() bool {
	return option.Config.EnableGoogleMultiNIC && e.deviceType != EndpointDeviceVETH
}

// GetDeviceType returns the device type of the endpoint.
func (e *Endpoint) GetDeviceType() EndpointDeviceType {
	return e.deviceType
}

// SetDeviceTypeForTest sets the device type of the endpoint.
func (e *Endpoint) SetDeviceTypeForTest(t EndpointDeviceType) {
	e.deviceType = t
}

// BPFMapPath returns the path to the ipvlan/macvtap tail call map of an endpoint.
func (e *Endpoint) BPFMapPath() string {
	return bpf.LocalMapPath(MacvtapMapName, e.ID)
}

// GetInterfaceNameInPod returns the interface name inside the pod namespace.
func (e *Endpoint) GetInterfaceNameInPod() string {
	return e.ifNameInPod
}

// GetNetNS returns the Linux network namespace of the container.
func (e *Endpoint) GetNetNS() string {
	return e.netNs
}

// IsMultiNIC retrurns if the endpoint is a multinic endpoint.
func (ep *epInfoCache) IsMultiNIC() bool {
	return ep.deviceType != EndpointDeviceVETH
}

func (e *Endpoint) DeleteLocalRedirectMapIfNecessary() error {
	if _, found := e.OpLabels.GetIdentityLabel("remote-redir-from"); found {
		return localredirect.LocalRedirectMap.Delete(
			&localredirect.LocalRedirectKey{Id: uint64(42)},
		)
	}
	return nil
}

func (e *Endpoint) UpdateLocalRedirectMap(newLabels, oldLabels labels.Labels) error {
	var hasOldLabel, hasNewLabel bool
	if oldLabels == nil {
		hasOldLabel = false
	} else {
		_, hasOldLabel = oldLabels["remote-redir-from"]
	}

	_, hasNewLabel = newLabels["remote-redir-from"]

	if hasOldLabel && !hasNewLabel {
		return localredirect.LocalRedirectMap.Delete(
			&localredirect.LocalRedirectKey{Id: 42},
		)
	}
	if hasNewLabel {
		return e.updateLocalRedirectMap(42)
	}
	return nil
}

func (e *Endpoint) updateLocalRedirectMap(key uint64) error {
	var epMac types.MACAddr
	for i, b := range e.LXCMac() {
		epMac[i] = b
	}
	return localredirect.LocalRedirectMap.Update(
		&localredirect.LocalRedirectKey{Id: key},
		&localredirect.LocalRedirectInfo{IfIndex: uint16(e.GetIfIndex()), IfMac: epMac},
	)
}
