package cmd

import (
	"context"
	"errors"
	"fmt"
	"hash/crc32"
	"sync"
	"time"

	v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/vishvananda/netlink"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/api"
	"github.com/cilium/cilium/pkg/datapath/connector"
	"github.com/cilium/cilium/pkg/endpoint"
	endpointid "github.com/cilium/cilium/pkg/endpoint/id"
	"github.com/cilium/cilium/pkg/endpoint/regeneration"
	multinicep "github.com/cilium/cilium/pkg/gke/multinic/endpoint"
	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maps/multinicdev"
	"github.com/cilium/cilium/pkg/option"
	"github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8slabels "k8s.io/apimachinery/pkg/labels"
	networkv1 "k8s.io/cloud-provider-gcp/crd/apis/network/v1"
	"k8s.io/utils/pointer"
	utilpointer "k8s.io/utils/pointer"

	. "github.com/cilium/cilium/api/v1/server/restapi/endpoint"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
)

const (
	listNetworkTimeout        = time.Second * 5
	maxNameLength             = 253
	podNameLabel              = "podName"
	networkLabel              = "network"
	networkInterfaceFinalizer = "networking.gke.io/network-interface-finalizer"
)

// errorDuringMultiNICCreation deletes all exposed multinic endpoints when an error occurs during creation.
func (d *Daemon) errorDuringMultiNICCreation(primaryEp *endpoint.Endpoint, code int, err error) ([]*endpoint.Endpoint, int, error) {
	eps := d.endpointManager.LookupEndpointsByContainerID(primaryEp.GetContainerID())
	for _, e := range eps {
		var errs []error
		if e.IsMultiNIC() {
			errs = d.deleteMultiNICEndpointQuiet(e, endpoint.DeleteConfig{
				// For multinic endpoints, the IPAM is external so no need to release IP.
				NoIPRelease: true,
			}, false)
		} else {
			errs = d.deleteEndpointQuiet(e, endpoint.DeleteConfig{
				// Since the IP expiration timer is already stopped for the primary endpoint
				// if it's not using external IPAM. We need to release IP while deleting it.
				NoIPRelease: e.DatapathConfiguration.ExternalIpam,
			})
		}
		for _, err := range errs {
			e.Logger(daemonSubsys).WithError(err).Warning("Ignoring error while deleting endpoint after creation failure")
		}
	}
	primaryEp.Logger(daemonSubsys).WithError(err).Warning("Creation of multinic endpoint failed")
	metrics.MultiNetworkPodCreation.WithLabelValues(metrics.LabelValueOutcomeFail).Inc()
	return nil, code, err
}

// errorWithMultiNICCleanup is called to execute proper clean up operations for the
// macvtap/macvlan interface before successful multinic endpoint creation.
// Note: another approach is to use netlink apis to check the interface inside the pod-ns,
// find the interface type then call appropriate clean up function. In this way, we could
// merge to a single cleanup function like errorDuringMultiNICCreation. However,
// this requires to pass more arguments (ifNameInPod, srcIfName, netns and etc.) and it
// adds complexity to errorDuringMultiNICCreation which is supposed to be called
// throughout the createMultiNICEndpoints.
func (d *Daemon) errorWithMultiNICCleanup(primaryEp *endpoint.Endpoint, code int, err error, cleanup func()) ([]*endpoint.Endpoint, int, error) {
	if cleanup != nil {
		cleanup()
	}
	return d.errorDuringMultiNICCreation(primaryEp, code, err)
}

// createMultiNICEndpoints attempts to create the multinic endpoints corresponding to
// the provided endpoint change request and primary endpoint (assume it's already created).
func (d *Daemon) createMultiNICEndpoints(ctx context.Context, owner regeneration.Owner, primaryEpTemplate *models.EndpointChangeRequest, primaryEp *endpoint.Endpoint) ([]*endpoint.Endpoint, int, error) {
	epTemplate := primaryEpTemplate.DeepCopy()
	// Reset parameters from the primary endpoint template.
	epTemplate.ID = 0
	epTemplate.Addressing.IPV4 = ""
	epTemplate.Addressing.IPV6 = ""
	epTemplate.Addressing.IPV4ExpirationUUID = ""
	epTemplate.Addressing.IPV6ExpirationUUID = ""
	epTemplate.InterfaceNameInPod = ""
	epTemplate.DatapathConfiguration = &models.EndpointDatapathConfiguration{
		// Set ExternalIpam to true will skip the IP releasing when deleting the endpoint.
		ExternalIpam: true,
	}

	if !primaryEp.K8sNamespaceAndPodNameIsSet() {
		return d.errorDuringMultiNICCreation(primaryEp, PutEndpointIDInvalidCode, errors.New("k8s namespace and pod name are required to create multinic endpoints"))
	}

	if !k8s.IsEnabled() {
		return d.errorDuringMultiNICCreation(primaryEp, PutEndpointIDInvalidCode, errors.New("k8s needs to be enabled for multinic endpoint creation"))
	}

	podID := primaryEp.GetK8sNamespaceAndPodName()

	pod, _, _, _, annotations, err := d.fetchK8sLabelsAndAnnotations(primaryEp.K8sNamespace, primaryEp.K8sPodName)
	if err != nil {
		return d.errorDuringMultiNICCreation(primaryEp, PutEndpointIDInvalidCode, fmt.Errorf("unable to fetch k8s annotations for pod %q", podID))
	}

	if pod == nil {
		return d.errorDuringMultiNICCreation(primaryEp, PutEndpointIDInvalidCode, errors.New("k8s pod is not found"))
	}

	defaultInterface, interfaceAnnotation, err := fetchMultiNICAnnotation(annotations)
	if err == nil && interfaceAnnotation == nil {
		log.Debugf("Multinic annotation is not found for pod %q, expect this is not a multinic pod", podID)
		return nil, PutEndpointIDCreatedCode, nil
	}

	if err != nil {
		return d.errorDuringMultiNICCreation(primaryEp, PutEndpointIDInvalidCode,
			fmt.Errorf("failed to fetch multi-nic interface annotations for pod %q: %v", podID, err))
	}

	var disableSourceIPValidation bool
	if option.Config.AllowDisableSourceIPValidation {
		disableSourceIPValidation = (annotations[networkv1.DisableSourceIPValidationAnnotationKey] == networkv1.DisableSourceIPValidationAnnotationValTrue)
	}

	enableMulticast := (annotations[networkv1.EnableMulticastAnnotationKey] == networkv1.EnableMulticastAnnotationValTrue)

	log.WithFields(logrus.Fields{
		logfields.ContainerID: primaryEp.GetContainerID(),
		logfields.EndpointID:  primaryEp.StringID(),
		logfields.K8sPodName:  podID,
		"interfaceAnnotation": annotations[networkv1.InterfaceAnnotationKey],
	}).Info("Create multinic endpoint requests with primary endpoint")

	podResources, err := d.kubeletClient.GetPodResources(ctx, pod)
	if err != nil {
		return d.errorDuringMultiNICCreation(primaryEp, PutEndpointIDInvalidCode, fmt.Errorf("failed querying pod resources for pod %q: %v", podID, err))
	}

	// Get the Primary interface's veth peer ifindex inside the pod ns.
	redirectIfIndex, primaryVethNameInPod, err := getPrimaryInterfaceVethPeerIfIndex(podID,
		primaryEp.GetIfIndex(), epTemplate.NetworkNamespace)
	if err != nil {
		return d.errorDuringMultiNICCreation(primaryEp,
			PutEndpointIDInvalidCode, err)
	}

	var eps []*endpoint.Endpoint
	var podIPs networkv1.PodIPsAnnotation
	var defaultPodNetworkConfigured bool
	defaultPodNetworkMTU := d.mtuConfig.GetRouteMTU()
	// parentDevInUse tracks the use of parent device for the L2 interface.
	parentDevInUse := make(map[string]string)
	for _, ref := range interfaceAnnotation {
		skipEpCreation := false
		intfLog := log.WithFields(logrus.Fields{
			logfields.InterfaceInPod: ref.InterfaceName,
			logfields.K8sPodName:     podID,
		})
		intfLog.Info("Multinic endpoint request")

		multinicTemplate := epTemplate.DeepCopy()
		multinicTemplate.DatapathConfiguration.DisableSipVerification = disableSourceIPValidation
		multinicTemplate.DatapathConfiguration.EnableMulticast = enableMulticast
		isDefaultInterface := defaultInterface == ref.InterfaceName

		multinicTemplate.PodStackRedirectIfindex = int64(redirectIfIndex)

		intfCR, netCR, err := d.getInterfaceAndNetworkCR(ctx, &ref, pod)
		if err != nil {
			return d.errorDuringMultiNICCreation(primaryEp, PutEndpointIDInvalidCode, fmt.Errorf("failed getting interface and network CR for pod %q: %v", podID, err))
		}

		var cleanup func()
		var netParamsRef client.Object
		var skipRouteInstallation bool
		// Update the interface status of the primary endpoint.
		if intfCR != nil && networkv1.IsDefaultNetwork(intfCR.Spec.NetworkName) {
			primaryEp.Logger(daemonSubsys).WithField("interfaceCR", intfCR.Name).Debug("Updating interface status")
			intfCR.Status.IpAddresses = nil
			if ipv4 := primaryEp.GetIPv4Address(); ipv4 != "" {
				intfCR.Status.IpAddresses = append(intfCR.Status.IpAddresses, ipv4)
			}
			if ipv6 := primaryEp.GetIPv6Address(); ipv6 != "" {
				intfCR.Status.IpAddresses = append(intfCR.Status.IpAddresses, ipv6)
			}
			intfCR.Status.MacAddress = primaryEp.LXCMac().String()
			if netCR != nil {
				intfCR.Status.DNSConfig = netCR.Spec.DNSConfig
				intfCR.Status.Routes = netCR.Spec.Routes
				intfCR.Status.Gateway4 = netCR.Spec.Gateway4
			}
			intfCR.Status.PodName = utilpointer.StringPtr(primaryEp.GetK8sPodName())
		} else if intfCR != nil && netCR != nil {
			if netCR.Spec.ParametersRef != nil {
				if netParamsRef, err = d.multinicClient.GetNetworkParamObject(ctx, netCR.Spec.ParametersRef); err != nil {
					intfLog.WithField("network", netCR.Name).Infof("Failed to get network params ref %v", err)
				}
			}
			if netCR.Spec.Type == networkv1.L2NetworkType {
				if cleanup, err = connector.SetupL2Interface(ref.InterfaceName, pod.Name, podResources, netCR, intfCR, multinicTemplate, d.dhcpClient, d.ipam); err != nil {
					return d.errorWithMultiNICCleanup(primaryEp, PutEndpointIDInvalidCode, fmt.Errorf("failed setting up layer2 interface %q for pod %q: %v", intfCR.Name, podID, err), cleanup)
				}
				// We don't allow different L2 interfaces share the same parent device.
				if name, ok := parentDevInUse[multinicTemplate.ParentDeviceName]; ok {
					return d.errorWithMultiNICCleanup(primaryEp, PutEndpointIDInvalidCode, fmt.Errorf("same parent interface in use by %s and %s for pod %q", ref.InterfaceName, name, podID), cleanup)
				}
				parentDevInUse[multinicTemplate.ParentDeviceName] = ref.InterfaceName

			} else if netCR.Spec.Type == networkv1.L3NetworkType {
				if cleanup, err = connector.SetupL3Interface(ref.InterfaceName, pod.Name, podResources, netCR, intfCR, multinicTemplate, d.ipam, netParamsRef); err != nil {
					return d.errorWithMultiNICCleanup(primaryEp, PutEndpointIDInvalidCode, fmt.Errorf("failed setting up layer3 interface %q for pod %q: %v", intfCR.Name, podID, err), cleanup)
				}
			} else if netCR.Spec.Type == networkv1.DeviceNetworkType {
				cleanup, isDPDK, err := connector.SetupDeviceInterface(ref.InterfaceName, pod.Name, podResources, netCR, intfCR, multinicTemplate, netParamsRef)
				if err != nil {
					return d.errorWithMultiNICCleanup(primaryEp, PutEndpointIDInvalidCode, fmt.Errorf("failed setting up device interface %q for pod %q: %v", intfCR.Name, podID, err), cleanup)
				}
				skipEpCreation = true
				if isDPDK {
					if isDefaultInterface {
						return d.errorWithMultiNICCleanup(primaryEp, PutEndpointIDInvalidCode, fmt.Errorf("default interface for pod %q cannot be DPDK Device type interface %q", podID, intfCR.Name), cleanup)
					}
					skipRouteInstallation = true
				}
			} else {
				return d.errorDuringMultiNICCreation(primaryEp, PutEndpointIDInvalidCode, fmt.Errorf("network %q has invalid network type %v of the multinic endpoint for pod %q", netCR.Name, netCR.Spec.Type, podID))
			}

			addNetworkLabelIfMultiNICEnabled(multinicTemplate, intfCR.Spec.NetworkName)
			if !skipEpCreation {
				multinicEndpoint, code, err := d.createEndpoint(ctx, owner, multinicTemplate)
				if err != nil {
					return d.errorWithMultiNICCleanup(primaryEp, code, fmt.Errorf("failed creating multinic endpoint for pod %q with code %d: %v", podID, code, err), cleanup)
				}
				if multinicEndpoint.GetDeviceType() == multinicep.EndpointDeviceMACVTAP {
					skipRouteInstallation = true
				}
				intfLog.WithField(logfields.EndpointID, multinicEndpoint.StringID()).Info("Successful multinic endpoint request")
				eps = append(eps, multinicEndpoint)
				// TODO check if we need to do this for host-interface devices too
				for _, ip := range multinicEndpoint.IPs() {
					podIP := networkv1.PodIP{IP: ip.String(), NetworkName: netCR.Name}
					podIPs = append(podIPs, podIP)
				}
			} else {
				// the device typed networks pass out the ip using the multinicTemplate
				podIP := networkv1.PodIP{IP: multinicTemplate.Addressing.IPV4, NetworkName: netCR.Name}
				podIPs = append(podIPs, podIP)
			}

		}
		if intfCR != nil {
			networkName := intfCR.Spec.NetworkName
			if networkv1.IsDefaultNetwork(networkName) {
				defaultPodNetworkConfigured = true
			}
			if err := connector.SetupNetworkRoutes(ref.InterfaceName, intfCR, netCR, multinicTemplate.NetworkNamespace,
				isDefaultInterface, defaultPodNetworkMTU, skipRouteInstallation); err != nil {
				return d.errorWithMultiNICCleanup(primaryEp, PutEndpointIDInvalidCode, fmt.Errorf("failed setting up network %q for pod %q: %v", networkName, podID, err), nil)
			}
			intfLog.Infof("Successfully configure network %s", networkName)

			// Patch interface CR via multinicClient
			if err = d.multinicClient.PatchNetworkInterfaceStatus(ctx, intfCR); err != nil {
				return d.errorWithMultiNICCleanup(primaryEp, PutEndpointIDInvalidCode, fmt.Errorf("failed updating status of interface CR %q for pod %q: %v", intfCR.Name, podID, err), nil)
			}
			intfLog.Debugf("Successfully update interface CR %+v", intfCR)
		}
	}

	if !defaultPodNetworkConfigured {
		// Pod network is required to set up when the default interface
		// is not within the default pod-network.
		defaultPodNetworkCR, err := d.defaultNetwork(ctx)
		if err != nil {
			return d.errorDuringMultiNICCreation(primaryEp, PutEndpointIDInvalidCode, fmt.Errorf("default network CR is required if the default gateway is on multi-net interface: %v", err))
		}
		podInterfaceCR := convertNetworkSpecToInterface(defaultPodNetworkCR)
		if err := connector.SetupNetworkRoutes(primaryVethNameInPod, podInterfaceCR, nil, epTemplate.NetworkNamespace,
			false, defaultPodNetworkMTU, false); err != nil {
			return d.errorDuringMultiNICCreation(primaryEp, PutEndpointIDInvalidCode, fmt.Errorf("failed setting up default network %q for pod %q: %v", defaultPodNetworkCR.Name, podID, err))
		}
		primaryEp.Logger(daemonSubsys).Info("Pod network is configured")
	}

	if err = d.multinicClient.SetPodIPsAnnotation(ctx, pod, &podIPs); err != nil {
		return d.errorDuringMultiNICCreation(primaryEp, PutEndpointIDInvalidCode, fmt.Errorf("failed to set pod IPs annotation for pod %q: %v", podID, err))
	}

	if epTemplate.SyncBuildEndpoint {
		if err := waitForEndpointsFirstRegeneration(ctx,
			d.endpointManager.LookupEndpointsByContainerID(primaryEp.GetContainerID())); err != nil {
			return d.errorDuringMultiNICCreation(primaryEp, PutEndpointIDInvalidCode, err)
		}
	}

	metrics.MultiNetworkPodCreation.WithLabelValues(metrics.LabelValueOutcomeSuccess).Inc()
	return eps, PutEndpointIDCreatedCode, nil
}

// getPrimaryInterfaceVethPeerIfIndex takes the pod-network endpoint and
// returns the Ifindex and interface name inside the pod-ns,for the Link associated
// with the pod-network
func getPrimaryInterfaceVethPeerIfIndex(podID string, primaryEpIfIndex int, nsPath string) (int, string, error) {
	// The primary/veth interface will be used to redirect
	// traffic to the pod-ns kernel stack
	primaryLink, err := netlink.LinkByIndex(primaryEpIfIndex)
	if err != nil {
		return 0, "", fmt.Errorf("failed getting interface for"+
			" primary endpoint pod %q interface %x: %v",
			podID, primaryEpIfIndex, err)
	}

	if vethLink, ok := primaryLink.(*netlink.Veth); !ok {
		return 0, "", fmt.Errorf("primary endpoint is not a veth"+
			" interface pod %q: %v", podID, err)
	} else {
		redirectIndex, err := netlink.VethPeerIndex(vethLink)
		if err != nil {
			return 0, "", fmt.Errorf("could not find veth"+
				" peer index of primary"+
				" endpoint's interface pod %q"+
				": %v", podID, err)
		}
		// Find the interface inside the pod namespace
		var vethPeer netlink.Link
		findLink := func(ns.NetNS) error {
			vethPeer, err = netlink.LinkByIndex(redirectIndex)
			return err
		}
		err = ns.WithNetNSPath(nsPath, findLink)
		if err != nil {
			return 0, "", fmt.Errorf("failed to find veth peer link inside the pod ns: %v", err)
		}
		return redirectIndex, vethPeer.Attrs().Name, nil
	}
}

// getInterfaceAndNetworkCR gets interface and network CR by querying multinicClient object.
func (d *Daemon) getInterfaceAndNetworkCR(ctx context.Context, ref *networkv1.InterfaceRef, pod *v1.Pod) (*networkv1.NetworkInterface, *networkv1.Network, error) {
	if ref.Interface == nil && ref.Network == nil {
		return nil, nil, fmt.Errorf("both interface and network name are not set for the interface %q", ref.InterfaceName)
	}
	if ref.Interface != nil && ref.Network != nil {
		return nil, nil, fmt.Errorf("one and only one of interface or network name can be set for the interface %q", ref.InterfaceName)
	}

	var (
		intfCR      *networkv1.NetworkInterface
		err         error
		networkName string
	)

	if ref.Network != nil {
		networkName = *ref.Network
		if !networkv1.IsDefaultNetwork(networkName) {
			log.Info("Constructing network interface CR based on Network information")
			intfCR = constructNetworkInterfaceObject(ctx, networkName, pod)
			err = d.multinicClient.CreateNetworkInterface(ctx, intfCR)
			if err != nil {
				if k8sErrors.IsAlreadyExists(err) {
					log.Warnf("Failed creating interface CR - already exists %s/%s: %v. Re-using existing interface object.", pod.Namespace, intfCR.Name, err)
				} else {
					return nil, nil, fmt.Errorf("failed creating interface CR %s/%s: %v", pod.Namespace, intfCR.Name, err)
				}
			}
			log.Infof("Done constructing interface CR based on network info, interfaceObjName: %s", intfCR.Name)
		}
	} else if ref.Interface != nil {
		intfCR, err = d.getInterfaceCR(ctx, *ref.Interface, pod.Namespace)
		if err != nil {
			return nil, nil, err
		}
		networkName = intfCR.Spec.NetworkName
	}

	netCR, err := d.multinicClient.GetNetwork(ctx, networkName)
	if err != nil {
		return nil, nil, fmt.Errorf("failed getting network CR %s: %v", networkName, err)
	}
	return intfCR, netCR, nil
}

// getInterfaceCRForPod fetches the NetworkInterface object for the pod and network.
func (d *Daemon) getInterfaceCRForPod(ctx context.Context, ref networkv1.InterfaceRef, ns, podName string) (*networkv1.NetworkInterface, error) {
	if ref.Interface == nil && ref.Network == nil {
		return nil, fmt.Errorf("interface or network is not set for the interface %q", ref.InterfaceName)
	}
	if ref.Interface != nil {
		intfCR, err := d.getInterfaceCR(ctx, *ref.Interface, ns)
		if err != nil {
			return nil, err
		}
		return intfCR, nil
	}

	// Find the auto-generated NetworkInterface
	intfList, err := d.multinicClient.ListNetworkInterfaces(ctx, &client.ListOptions{
		Namespace: ns,
		LabelSelector: k8slabels.Set(map[string]string{
			podNameLabel: podName,
			networkLabel: *ref.Network,
		}).AsSelector(),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get interface CR for pod %s/%s with network %s: %v", ns, podName, *ref.Network, err)
	}
	if len(intfList.Items) == 0 {
		return nil, fmt.Errorf("NetworkInterface for pod %s/%s with network %s is not found", ns, podName, *ref.Network)
	}
	if len(intfList.Items) > 1 {
		return nil, fmt.Errorf("more than one NetworkInterface for pod %s/%s with network %s is found", ns, podName, *ref.Network)
	}
	return &intfList.Items[0], nil
}

// getInterfaceCR gets interface by querying multinicClient object.
func (d *Daemon) getInterfaceCR(ctx context.Context, name, ns string) (*networkv1.NetworkInterface, error) {
	intfCR, err := d.multinicClient.GetNetworkInterface(ctx, name, ns)
	if err != nil {
		return nil, fmt.Errorf("failed getting interface CR %s/%s: %v", ns, name, err)
	}

	return intfCR, nil
}

func constructNetworkInterfaceObject(ctx context.Context, networkName string, pod *v1.Pod) *networkv1.NetworkInterface {
	intf := &networkv1.NetworkInterface{
		ObjectMeta: metav1.ObjectMeta{
			Name:      generateInterfaceObjName(pod.Name, networkName),
			Namespace: pod.Namespace,
			Labels: map[string]string{
				podNameLabel: pod.Name,
				networkLabel: networkName,
			},
			Finalizers: []string{
				networkInterfaceFinalizer,
			},
			Annotations: map[string]string{
				networkv1.AutoGenAnnotationKey: networkv1.AutoGenAnnotationValTrue,
			},
			OwnerReferences: []metav1.OwnerReference{
				{
					Kind:       "Pod",
					APIVersion: "v1",
					Name:       pod.Name,
					UID:        pod.UID,
				},
			},
		},
		Spec: networkv1.NetworkInterfaceSpec{
			NetworkName: networkName,
		},
		Status: networkv1.NetworkInterfaceStatus{},
	}
	return intf
}

func truncate(s string, length int) string {
	if len(s) <= length {
		return s
	}
	return s[0:length]
}

// suffix returns a string constructed with the given network name and a hash.
// The interface name is kept as much as possible and the fingerprint is generated
// with the pod name using CRC-32 which has 8 character length.
func suffix(network, podName string) string {
	return fmt.Sprintf("-%s-%08x", network, crc32.ChecksumIEEE([]byte(podName)))
}

// generateInterfaceObjName generates the Network Interface CR name for the endpoint.
// If it's a multi NIC endpoint, the function appends a unique suffix to its pod name.
// The function honors the maximum character length when appending extra suffix.
func generateInterfaceObjName(podName string, network string) string {
	suffix := suffix(network, podName)
	return truncate(podName, maxNameLength-len(suffix)) + suffix
}

func (d *Daemon) deleteMultiNICEndpoint(ep *endpoint.Endpoint, podChanged bool) int {
	// Cancel any ongoing endpoint creation
	d.endpointCreations.CancelCreateRequest(ep)

	scopedLog := log.WithField(logfields.EndpointID, ep.ID)

	errs := d.deleteMultiNICEndpointQuiet(ep, endpoint.DeleteConfig{
		// Since endpoint is multinic, NoIPRelease is always true
		NoIPRelease: true,
	}, podChanged)
	for _, err := range errs {
		scopedLog.WithError(err).Warn("Ignoring error while deleting endpoint")
	}
	return len(errs)
}

func (d *Daemon) deleteMultiNICEndpointQuiet(ep *endpoint.Endpoint, conf endpoint.DeleteConfig, podChanged bool) []error {
	errs := d.endpointManager.RemoveEndpoint(ep, conf)
	ifName := ep.GetInterfaceName()
	ifNameInPod := ep.GetInterfaceNameInPod()
	netNS := ep.GetNetNS()
	deviceType := ep.GetDeviceType()
	ep.Logger(daemonSubsys).WithFields(logrus.Fields{
		logfields.Interface:      ifName,
		logfields.InterfaceInPod: ifNameInPod,
		logfields.NetNSName:      netNS,
		logfields.DeviceType:     deviceType,
	}).Info("Revert multinic endpoint setup")

	if ep.ExternalDHCPEnabled() {
		// If pod changed, then the interface lease is now maintained by a different pod. The lease should
		// not released and instead should just expire for this pod.
		d.dhcpClient.Release(ep.GetContainerID(), netNS, ifNameInPod, podChanged)
	} else {
		d.ipam.MultiNetworkAllocatorMutex.Lock()
		for _, allocator := range d.ipam.MultiNetworkAllocators {
			err := allocator.Release(ep.IPv4.IP())
			if err != nil {
				errs = append(errs, err)
			}
		}
		d.ipam.MultiNetworkAllocatorMutex.Unlock()
	}
	var err error
	switch deviceType {
	case multinicep.EndpointDeviceMACVTAP:
		err = connector.RevertMacvtapSetup(ifNameInPod, ifName, netNS)
	case multinicep.EndpointDeviceMACVLAN:
		err = connector.DeleteInterfaceInRemoteNs(ifNameInPod, netNS)
	case multinicep.EndpointDeviceIPVLAN:
		err = connector.DeleteInterfaceInRemoteNs(ifNameInPod, netNS)
	case multinicep.EndpointDeviceMultinicVETH:
		err = connector.DeleteInterfaceInRemoteNs(ifNameInPod, netNS)
	default:
		err = fmt.Errorf("unsupported device type %q", deviceType)
	}
	if err != nil {
		errs = append(errs, err)
	}

	return errs
}

func (d *Daemon) restoreInterfaceIfDeviceNetwork(ctx context.Context, ref networkv1.InterfaceRef, netns string) error {
	netCR, err := d.multinicClient.GetNetwork(ctx, *ref.Network)
	if err != nil {
		return fmt.Errorf("Failed to fetch Network %s: %v", *ref.Network, err)
	}
	log.Debugf("got netCR: %v", netCR)
	if netCR.Spec.Type != networkv1.DeviceNetworkType {
		return nil
	}
	log.Infof("Restoring device for Device network %s.", netCR.Name)
	netParamsRef, err := d.multinicClient.GetNetworkParamObject(ctx, netCR.Spec.ParametersRef)
	if err != nil {
		return fmt.Errorf("Error getting params object %s for network %s: %v", netCR.Spec.ParametersRef.Name, netCR.Name, err)
	}
	if err := connector.RevertDeviceInterface(ref.InterfaceName, netCR, netns, netParamsRef); err != nil {
		return fmt.Errorf("Error reverting Device network %v: %v", netCR.Name, err)
	}
	return nil
}

// DeleteEndpoints deletes all the endpoints for the given id.
// Only called when EnableGoogleMultiNIC is enabled.
func (d *Daemon) DeleteEndpoints(ctx context.Context, id string) (int, error) {
	prefix, eid, err := endpointid.Parse(id)
	if err != nil {
		return 0, api.Error(DeleteEndpointIDInvalidCode, err)
	}

	var eps []*endpoint.Endpoint
	switch prefix {
	case endpointid.ContainerIdPrefix:
		eps = d.endpointManager.LookupEndpointsByContainerID(eid)
	case endpointid.PodNamePrefix:
		eps = d.endpointManager.LookupEndpointsByPodName(eid)
	default:
		return d.DeleteEndpoint(id)
	}

	if len(eps) == 0 {
		return 0, api.New(DeleteEndpointIDNotFoundCode, "endpoints %q not found", id)
	}

	podName := eps[0].K8sPodName
	podNS := eps[0].K8sNamespace

	_, _, _, _, annotations, err := d.fetchK8sLabelsAndAnnotations(podNS, podName)
	if err != nil {
		log.WithFields(logrus.Fields{
			logfields.K8sPodName: podName,
			"error":              err,
		}).Error("Failed to fetch annotations from pod when deleting multinic endpoints")
	}
	var nerrs int
	var interfaceAnnotation networkv1.InterfaceAnnotation
	ifNameToInterfaceCR := map[string]*networkv1.NetworkInterface{}
	if len(annotations) > 0 {
		_, interfaceAnnotation, err = fetchMultiNICAnnotation(annotations)
		if err == nil && interfaceAnnotation == nil {
			log.Debugf("Multinic annotation is not found for pod %s/%s, expect this is not a multinic pod", podNS, podName)
		}
		if err != nil {
			log.Errorf("failed to fetch multi-nic annotations for pod %s/%s: %v", podNS, podName, err)
			nerrs++
		} else {
			for _, ref := range interfaceAnnotation {
				if ref.Network != nil {
					err := d.restoreInterfaceIfDeviceNetwork(ctx, ref, eps[0].GetNetNS())
					if err != nil {
						log.Errorf("%v", err)
						nerrs++
					}
				}
				if ref.Network != nil && networkv1.IsDefaultNetwork(*ref.Network) {
					continue
				}
				intfCR, err := d.getInterfaceCRForPod(ctx, ref, podNS, podName)
				if err != nil {
					log.Errorf("Errored getting interface during endpoint deletion: %q", err)
					nerrs++
					continue
				}
				ifNameToInterfaceCR[ref.InterfaceName] = intfCR
			}
		}
	}

	log.Infof("Deleting %d endpoints for id %s", len(eps), id)
	for _, ep := range eps {
		log.WithFields(logrus.Fields{
			logfields.IPv4:        ep.GetIPv4Address(),
			logfields.IPv6:        ep.GetIPv6Address(),
			logfields.ContainerID: ep.GetShortContainerID(),
		}).Info("Delete endpoint request")
		if err := endpoint.APICanModify(ep); err != nil {
			return 0, api.Error(DeleteEndpointIDInvalidCode, err)
		}
		if ep.IsMultiNIC() {
			intfCR := ifNameToInterfaceCR[ep.GetInterfaceNameInPod()]
			// In case we were unable to gather the interface or the podName is not set,
			// we treat it the same as podChanged=true which will mean that the lease will expire. We rather let the lease expire if
			// we do not know whether it is a pod shutdown or not

			var currentPod string
			if intfCR != nil && intfCR.Status.PodName != nil {
				currentPod = *intfCR.Status.PodName
			}
			podChanged := currentPod != ep.GetK8sPodName()
			if intfCR != nil && intfCR.Status.MacAddress == "" {
				log.Warningf("interface CR %s/%s status does not have mac address set ", intfCR.Namespace, intfCR.Name)
				// Let the lease expire to be on the safe side.
				podChanged = true
			}
			log.WithFields(logrus.Fields{
				"previousPod": ep.GetK8sPodName(),
				"currentPod":  currentPod,
			}).Info("Deleting multinic endpoint")
			nerrs += d.deleteMultiNICEndpoint(ep, podChanged)
		} else {
			nerrs += d.deleteEndpoint(ep)
		}
	}

	for _, intfCR := range ifNameToInterfaceCR {
		if controllerutil.ContainsFinalizer(intfCR, networkInterfaceFinalizer) {
			newIntfCR := intfCR.DeepCopy()
			controllerutil.RemoveFinalizer(newIntfCR, networkInterfaceFinalizer)
			if err := d.multinicClient.PatchNetworkInterface(ctx, intfCR, newIntfCR); err != nil {
				log.Errorf("Patching NetworkInterface %s/%s failed: %v", intfCR.Namespace, intfCR.Name, err)
				nerrs++
			}
		}
	}
	return nerrs, nil
}

// addNetworkLabelIfMultiNICEnabled appends a network label to the existing labels in the
// endpoint template. e.g. networking.gke.io/network: vlan-100, networking.gke.io/network: pod-network.
func addNetworkLabelIfMultiNICEnabled(epTemplate *models.EndpointChangeRequest, network string) {
	if !option.Config.EnableGoogleMultiNIC {
		return
	}
	log.WithFields(logrus.Fields{
		"addressing":         epTemplate.Addressing,
		logfields.DeviceType: epTemplate.DeviceType,
		"network":            network,
	}).Info("Add multi-network label")
	epTemplate.Labels = append(epTemplate.Labels, labels.GetMultiNICNetworkLabel(network))
}

// cleanupMultiNICDevMap cleans up entries that's not in the endpoint list.
func cleanupMultiNICDevMap(eps []*endpoint.Endpoint) {
	if option.Config.DryMode || !option.Config.EnableGoogleMultiNIC {
		return
	}
	existing, err := multinicdev.DumpToMap()
	if err != nil {
		log.WithError(err).Warning("Unable to open multinicdev map while restoring. Skipping cleanup of multinicdev map on startup")
		return
	}
	for _, ep := range eps {
		if !ep.IsMultiNIC() {
			continue
		}
		delete(existing, ep.LXCMac().String())
	}
	for toDel, info := range existing {
		if err := multinicdev.DeleteEntry(toDel); err != nil {
			log.WithError(err).Warn("Unable to delete obsolete device from multinicdev map")
		} else {
			log.Debugf("Removed outdated device (%s, %d) from multinicdev map", toDel, info.EndpointID)
		}
	}
	return
}

// fetchMultiNICAnnotation returns the default interface name and interface annotation from the provided
// annotations. The function also verifies the default interface must be specified and referenced in
// the interface annotation. Otherwise, an error is returned.
func fetchMultiNICAnnotation(annotations map[string]string) (string, networkv1.InterfaceAnnotation, error) {
	interfaces, ok := annotations[networkv1.InterfaceAnnotationKey]
	if !ok {
		// This is not a multi-nic pod since the interface annotation is not found.
		return "", nil, nil
	}
	defaultInterface, ok := annotations[networkv1.DefaultInterfaceAnnotationKey]
	if !ok {
		return "", nil, errors.New("default interface must be specified for multi-nic pod")
	}
	interfaceAnnotation, err := networkv1.ParseInterfaceAnnotation(interfaces)
	if err != nil {
		return "", nil, fmt.Errorf("failed to parse interface annotation: %v", err)
	}
	for _, ref := range interfaceAnnotation {
		if ref.InterfaceName == defaultInterface {
			return defaultInterface, interfaceAnnotation, nil
		}
	}
	return "", nil, fmt.Errorf("default interface %q must be referenced in the interface annotation %s", defaultInterface, interfaces)
}

func convertNetworkSpecToInterface(network *networkv1.Network) *networkv1.NetworkInterface {
	if network == nil {
		return nil
	}

	return &networkv1.NetworkInterface{
		Spec: networkv1.NetworkInterfaceSpec{
			NetworkName: network.Name,
		},
		Status: networkv1.NetworkInterfaceStatus{
			Routes:   network.Spec.Routes,
			Gateway4: network.Spec.Gateway4,
		},
	}
}

func isMultiNICPod(annotations map[string]string) bool {
	_, ok := annotations[networkv1.InterfaceAnnotationKey]
	return ok && option.Config.EnableGoogleMultiNIC
}

func waitForEndpointsFirstRegeneration(ctx context.Context, eps []*endpoint.Endpoint) error {
	var (
		wg   sync.WaitGroup
		merr []error
	)
	for _, e := range eps {
		ep := e
		wg.Add(1)
		go func() {
			if err := ep.WaitForFirstRegeneration(ctx); err != nil {
				ep.Logger(daemonSubsys).WithError(err).Warning("WaitForFirstRegeneration failed")
				merr = append(merr, err)
			}
			wg.Done()
		}()
	}
	wg.Wait()
	if len(merr) != 0 {
		return fmt.Errorf("there are %d endpoints failed WaitForFirstRegeneration", len(merr))
	}
	return nil
}

func setDataPathConfigurationForMultiNIC(ep *models.EndpointChangeRequest) {
	if !option.Config.EnableGoogleMultiNIC {
		return
	}
	switch ep.DeviceType {
	case multinicep.EndpointDeviceMultinicVETH:
		// L3 multinic endpoint
		ep.DatapathConfiguration.RequireRouting = pointer.BoolPtr(true)
		ep.DatapathConfiguration.RequireArpPassthrough = false
		ep.DatapathConfiguration.InstallEndpointRoute = false
	case multinicep.EndpointDeviceMACVLAN, multinicep.EndpointDeviceMACVTAP:
		// L2 multinic endpoint
		// Disable routing and enable arp passthrough for L2 support.
		ep.DatapathConfiguration.RequireArpPassthrough = true
		ep.DatapathConfiguration.RequireRouting = pointer.BoolPtr(false)
	}
}

// defaultNetwork retrieves the default network in the cluster.
// For compatibility concerns, the function first search "default" network,
// then fallbacks to "pod-network" if "default" doesn't exist.
// TODO(b/272608138): Remove the fallback logic once the migration is done in ABM.
func (d *Daemon) defaultNetwork(ctx context.Context) (*networkv1.Network, error) {
	var defaultNetwork *networkv1.Network
	var err error
	if _, defaultNetwork, err = d.getInterfaceAndNetworkCR(ctx, &networkv1.InterfaceRef{Network: utilpointer.StringPtr(networkv1.DefaultPodNetworkName)}, nil); err == nil {
		return defaultNetwork, nil
	}
	log.Debugf("Error looking for default network: %v; fallback to pod-network", err)
	// Fallback to "pod-network" if "default" network is not found.
	if _, defaultNetwork, err = d.getInterfaceAndNetworkCR(ctx, &networkv1.InterfaceRef{Network: utilpointer.StringPtr(networkv1.DefaultNetworkName)}, nil); err != nil {
		return nil, fmt.Errorf("default network %q: %v", networkv1.DefaultNetworkName, err)
	}
	return defaultNetwork, nil
}
