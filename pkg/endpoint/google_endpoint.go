package endpoint

import (
	"fmt"
	"hash/crc32"
	"runtime"
	"unsafe"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/gke/features"
	multinicep "github.com/cilium/cilium/pkg/gke/multinic/endpoint"
	"github.com/cilium/cilium/pkg/gke/multinic/multinicconfig"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/mac"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
	"golang.org/x/sys/unix"
)

const (
	// MultiNICMapName specifies the tail call map for EP on both egress and ingress used with multinic.
	MultiNICMapName = "cilium_multinic_"
	// maxNameLength is the maximum character length for the CEP object name.
	maxNameLength = 253
)

// IsMultiNIC returns true if the endpoint is a multi-networking endpoint.
func (e *Endpoint) IsMultiNIC() bool {
	return e.deviceType != multinicep.EndpointDeviceVETH
}

// IsMultiNICHost returns true if the endpoint is a multi nic host.
func (e *Endpoint) IsMultiNICHost() bool {
	return e.IsHost() && !e.IsDefaultHost()
}

// IsPerimeter returns true if the endpoint is a perimeter endpoint.
func (e *Endpoint) IsPerimeter() bool {
	alllabels := e.OpLabels.AllLabels()
	perimeterNetworkLabelStr := labels.GetMultiNICNetworkLabel(features.GlobalConfig.PerimeterEndpointNetwork)
	perimeterNetworkLabel := labels.ParseLabel(perimeterNetworkLabelStr)
	return alllabels.Has(perimeterNetworkLabel)
}

// IsDefaultHost returns true for the default host endpoint.
func (e *Endpoint) IsDefaultHost() bool {
	return e.IsHost() && (e.nodeNetworkName == "" || e.nodeNetworkName == identity.DefaultMultiNICNodeNetwork)
}

// GetDeviceType returns the device type of the endpoint.
func (e *Endpoint) GetDeviceType() multinicep.EndpointDeviceType {
	return e.deviceType
}

// GetDeviceTypeIndex returns multinic endpoint type as int.
func (e *Endpoint) GetDeviceTypeIndex() int {
	switch e.deviceType {
	case multinicep.EndpointDeviceVETH:
		return multinicep.EndpointDeviceIndexVETH
	case multinicep.EndpointDeviceMultinicVETH:
		return multinicep.EndpointDeviceIndexMultinicVETH
	case multinicep.EndpointDeviceMACVTAP:
		return multinicep.EndpointDeviceIndexMACVTAP
	case multinicep.EndpointDeviceMACVLAN:
		return multinicep.EndpointDeviceIndexMACVLAN
	case multinicep.EndpointDeviceIPVLAN:
		return multinicep.EndpointDeviceIndexIPVLAN
	default:
		return multinicep.EndpointDeviceIndexVETH
	}
}

// SetDeviceTypeForTest sets the device type of the endpoint.
func (e *Endpoint) SetDeviceTypeForTest(t multinicep.EndpointDeviceType) {
	e.deviceType = t
}

// BPFMapPath returns the path to the ipvlan/macvtap/macvlan tail call map of an endpoint.
func (e *Endpoint) BPFMapPath() string {
	return bpf.LocalMapPath(MultiNICMapName, e.ID)
}

// PinDatapathMap retrieves a file descriptor from the map ID from the API call
// and pins the corresponding map into the BPF file system.
func (e *Endpoint) PinDatapathMap() error {
	if err := e.lockAlive(); err != nil {
		return err
	}
	defer e.unlock()
	return e.pinDatapathMap()
}

func (e *Endpoint) pinDatapathMap() error {
	if e.datapathMapID == 0 {
		return nil
	}

	mapFd, err := mapFdFromID(e.datapathMapID)
	if err != nil {
		return err
	}
	defer unix.Close(mapFd)

	return objPin(mapFd, e.BPFMapPath())
}

// GetContainerInterfaceName returns the interface name inside the pod namespace.
func (e *Endpoint) GetContainerInterfaceName() string {
	return e.containerIfName
}

// GetNetNS returns the Linux network namespace of the container.
func (e *Endpoint) GetNetNS() string {
	return e.netNs
}

func truncate(s string, length int) string {
	if len(s) <= length {
		return s
	}
	return s[0:length]
}

// suffix returns a string constructed with the given interface name and pod name hash.
// The interface name is kept as much as possible and the fingerprint is generated
// with the pod name using CRC-32 which has 8 character length.
func suffix(ifName, podName string) string {
	return fmt.Sprintf("-%s-%08x", ifName, crc32.ChecksumIEEE([]byte(podName)))
}

// GetParentDevIndex returns the parent device ifindex.
// Returns 0 if it's not multinic endpoint.
func (ep *Endpoint) GetParentDevIndex() int {
	if !ep.IsMultiNIC() {
		return 0
	}
	return ep.parentDevIndex
}

// GetParentDevMac returns the mac of the parent device.
// Currently, enabled only for EndpointDeviceMultinicVETH, and returns 00 MAC
// for others.
func (ep *Endpoint) GetParentDevMac() mac.MAC {
	if ep.deviceType != multinicep.EndpointDeviceMultinicVETH {
		return mac.MAC([]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	}
	return ep.parentDevMac
}

// GetEpInfoCacheForCurrentDir returns endpoint info cache for the current directory.
func (e *Endpoint) GetEpInfoCacheForCurrentDir() (*epInfoCache, error) {
	if err := e.lockAlive(); err != nil {
		return nil, err
	}
	epInfo := e.createEpInfoCache(e.StateDirectoryPath())
	e.unlock()
	return epInfo, nil
}

// GetPodStackRedirectIfindex returns the ifIndex for the interface which
// can be used to get a packet to the pod-ns from within the pod-ns.
func (e *Endpoint) GetPodStackRedirectIfindex() int {
	return e.podStackRedirectIfindex
}

// ExternalDHCPEnabled returns whether the endpoint has external dhcp enabled.
func (e *Endpoint) ExternalDHCPEnabled() bool {
	return e.externalDHCP4
}

// IsIPVlan returns if the endpoint is a multinic endpoint of type IPVlan.
func (e *Endpoint) IsIPVlan() bool {
	return multinicconfig.Enabled() && e.deviceType == multinicep.EndpointDeviceIPVLAN
}

// EnableMulticast returns true if the endpoint allows multicast traffic.
func (e *Endpoint) EnableMulticast() bool {
	return e.DatapathConfiguration.EnableMulticast
}

// GetNetworkID returns the network ID of the multinic endpoint.
// Currently, enabled only for EndpointDeviceMultinicVETH, and returns 0
// for others.
func (e *Endpoint) GetNetworkID() uint32 {
	if e.deviceType != multinicep.EndpointDeviceMultinicVETH {
		return 0
	}
	return e.DatapathConfiguration.NetworkID
}

// SetParentDevName sets the parent device name.
func (ep *Endpoint) SetParentDevName(dev string) {
	ep.parentDevName = dev
}

// GetParentDevName gets the parent device name.
func (ep *Endpoint) GetParentDevName() string {
	return ep.parentDevName
}

// SetNodeNetworkName sets the node network name.
// If the endpoint is not multi nic host, this does nothing.
func (ep *Endpoint) SetNodeNetworkName(network string) {
	if !option.Config.EnableGoogleMultiNICHostFirewall {
		return
	}
	ep.nodeNetworkName = network
}

// GetNodeNetworkName gets the node network name.
func (ep *Endpoint) GetNodeNetworkName() string {
	return ep.nodeNetworkName
}

// populateNodeNetwork restores the node network from the reserved label
// during the endpoint restoration from a directory on the node.
func (ep *Endpoint) populateNodeNetwork() {
	if !option.Config.EnableGoogleMultiNICHostFirewall {
		return
	}
	ep.unconditionalLock()
	defer ep.unlock()

	allEpLabels := ep.OpLabels.AllLabels()
	for _, lbl := range allEpLabels {
		if lbl.IsReservedSource() && lbl.Key == labels.IDNameMultiNICHost {
			ep.SetNodeNetworkName(lbl.Value)
			return
		}
	}
}

type bpfAttrFdFromId struct {
	ID     uint32
	NextID uint32
	Flags  uint32
}

// mapFdFromID retrieves a file descriptor based on a map ID.
func mapFdFromID(id int) (int, error) {
	uba := bpfAttrFdFromId{
		ID: uint32(id),
	}
	const BPF_MAP_GET_FD_BY_ID = 14
	fd, _, err := unix.Syscall(
		unix.SYS_BPF,
		BPF_MAP_GET_FD_BY_ID,
		uintptr(unsafe.Pointer(&uba)),
		unsafe.Sizeof(uba),
	)
	runtime.KeepAlive(&uba)

	if fd == 0 || err != 0 {
		return 0, fmt.Errorf("Unable to get object fd from id %d: %s", id, err)
	}

	return int(fd), nil
}

// This struct must be in sync with union bpf_attr's anonymous struct used by
// BPF_OBJ_*_ commands
type bpfAttrObjOp struct {
	pathname uint64
	fd       uint32
	pad0     [4]byte
}

// objPin stores the map's fd in pathname.
func objPin(fd int, pathname string) error {
	pathStr, err := unix.BytePtrFromString(pathname)
	if err != nil {
		return fmt.Errorf("Unable to convert pathname %q to byte pointer: %w", pathname, err)
	}
	uba := bpfAttrObjOp{
		pathname: uint64(uintptr(unsafe.Pointer(pathStr))),
		fd:       uint32(fd),
	}
	const BPF_OBJ_PIN = 6
	ret, _, errno := unix.Syscall(
		unix.SYS_BPF,
		BPF_OBJ_PIN,
		uintptr(unsafe.Pointer(&uba)),
		unsafe.Sizeof(uba),
	)
	runtime.KeepAlive(pathStr)
	runtime.KeepAlive(&uba)

	if ret != 0 || errno != 0 {
		return fmt.Errorf("Unable to pin object with file descriptor %d to %s: %s", fd, pathname, errno)
	}

	return nil
}

func (e *Endpoint) ParentInterfaceIP() (string, error) {
	if e.IsMultiNIC() && multinicconfig.GlobalConfig.EnableGoogleTunnelThroughSecondaryInterfaces {
		ip, err := node.FirstV4GlobalAddrOnInf(e.parentDevName)
		if err != nil {
			return "", err
		}
		return ip, nil
	}
	return "", nil
}

func (e *Endpoint) setGoogleConfig() bool {
	if option.Config.AllowDisableSourceIPValidation {
		if e.DatapathConfiguration.DisableSipVerification {
			return e.applyOptsLocked(option.OptionMap{option.SourceIPVerification: option.OptionDisabled})
		}
	}
	return false
}
