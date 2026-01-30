package cmd

import (
	"context"
	"fmt"
	"hash/crc32"
	"net/netip"
	"reflect"
	"slices"
	"sync"

	"errors"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/time"

	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/ipam"
	v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/node"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/vishvananda/netlink"
	"sigs.k8s.io/controller-runtime/pkg/client"

	networkv1 "github.com/GoogleCloudPlatform/gke-networking-api/apis/network/v1"
	"github.com/cilium/cilium/pkg/api"
	"github.com/cilium/cilium/pkg/datapath/connector"
	"github.com/cilium/cilium/pkg/endpoint"
	endpointid "github.com/cilium/cilium/pkg/endpoint/id"
	"github.com/cilium/cilium/pkg/endpoint/regeneration"
	multinicep "github.com/cilium/cilium/pkg/gke/multinic/endpoint"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maps/multinicdev"
	"github.com/cilium/cilium/pkg/option"
	"github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/pointer"
	utilpointer "k8s.io/utils/pointer"
	"k8s.io/utils/ptr"

	ipamv1alpha1 "gke-internal.googlesource.com/anthos-networking/ipam-controller/api/v1alpha1"

	. "github.com/cilium/cilium/api/v1/server/restapi/endpoint"
	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
)

const (
	listNetworkTimeout = time.Second * 5
	maxNameLength      = 253
	podNameLabel       = "podName"
	networkLabel       = "network"
)

// CreateEndpoint implements epqueue.EndpointCreationSink.
func (d *Daemon) CreateEndpoint(ctx context.Context, endpoint *models.EndpointChangeRequest) error {
	ep, _, err := d.createEndpoint(ctx, d, endpoint)
	if err != nil {
		return fmt.Errorf("create queued endpoint for %s/%s: %w", endpoint.K8sNamespace, endpoint.K8sPodName, err)
	}
	ep.Logger(daemonSubsys).Info("Successful endpoint creation")
	return nil
}

// errorDuringMultiNICCreation deletes all exposed multinic endpoints when an error occurs during creation.
func (d *Daemon) errorDuringMultiNICCreation(primaryEp *endpoint.Endpoint, code int, err error) ([]*endpoint.Endpoint, int, error) {
	eps := d.endpointManager.GetEndpointsByContainerID(primaryEp.GetContainerID())
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
		log.Infof("executing cleanup for %s", primaryEp.K8sPodName)
		cleanup()
	}
	return d.errorDuringMultiNICCreation(primaryEp, code, err)
}

// releaseMultiNICIPByTemplate releases IPv4 addresses associated with the multi-nic template to
// be reserved for the endpoint.
func (d *Daemon) releaseMultiNICIPByTemplate(multinicTemplate *models.EndpointChangeRequest) {
	d.ipam.MultiNetworkAllocatorMutex.Lock()
	defer d.ipam.MultiNetworkAllocatorMutex.Unlock()

	if multinicTemplate.Addressing.IPV4 == "" {
		log.Warning("no IPV4 address to release")
		return
	}
	ipAddr, err := netip.ParseAddr(multinicTemplate.Addressing.IPV4)
	if err != nil {
		log.Warningf("failed to parse IP addresses: %s", multinicTemplate.Addressing.IPV4)
		return
	}

	for _, allocator := range d.ipam.MultiNetworkAllocators {
		if ipAddr.Is4() {
			if err := allocator.Release(ipAddr.AsSlice(), ipam.PoolDefault()); err != nil {
				log.WithError(err).Errorf("unable to release IP %s", ipAddr.String())
			}
		}
	}
}

// createMultiNICEndpoints attempts to create the multinic endpoints corresponding to
// the provided endpoint change request and primary endpoint (assume it's already created).
func (d *Daemon) createMultiNICEndpoints(ctx context.Context, multiNICWaitCh chan struct{}, owner regeneration.Owner, primaryEpTemplate *models.EndpointChangeRequest, primaryEp *endpoint.Endpoint) ([]*endpoint.Endpoint, int, error) {
	epTemplate := primaryEpTemplate.DeepCopy()
	// Reset parameters from the primary endpoint template.
	epTemplate.ID = 0
	epTemplate.Addressing.IPV4 = ""
	epTemplate.Addressing.IPV6 = ""
	epTemplate.Addressing.IPV4ExpirationUUID = ""
	epTemplate.Addressing.IPV6ExpirationUUID = ""
	epTemplate.DatapathConfiguration = &models.EndpointDatapathConfiguration{
		// Set ExternalIpam to true will skip the IP releasing when deleting the endpoint.
		ExternalIpam: true,
	}

	if !primaryEp.K8sNamespaceAndPodNameIsSet() {
		return d.errorDuringMultiNICCreation(primaryEp, PutEndpointIDInvalidCode, errors.New("k8s namespace and pod name are required to create multinic endpoints"))
	}

	if !d.clientset.IsEnabled() {
		return d.errorDuringMultiNICCreation(primaryEp, PutEndpointIDInvalidCode, errors.New("k8s needs to be enabled for multinic endpoint creation"))
	}

	podID := primaryEp.GetK8sNamespaceAndPodName()

	var cleanup = func() {
		log.Infof("No resources to cleanup for primary endpoint %s", podID)
	}

	pod, metadata, err := d.fetchK8sMetadataForEndpoint(primaryEp.K8sNamespace, primaryEp.K8sPodName)
	annotations := metadata.Annotations
	if err != nil {
		return d.errorDuringMultiNICCreation(primaryEp, PutEndpointIDInvalidCode, fmt.Errorf("unable to fetch k8s annotations for pod %q: %v", podID, err))
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

	multinicTemplate := epTemplate.DeepCopy()
	// Start a goroutine to monitor context cancellation and trigger cleanup for endpoints.
	// NOTE: an ideal (future) solution will include passing the ctx down into every function and check ctx.Done along the way.
	go func() {
		select {
		case <-ctx.Done():
			err := fmt.Errorf("context cancelled or timed out, triggering cleanup for primary endpoint %s", podID)
			d.errorWithMultiNICCleanup(primaryEp, PutEndpointIDInvalidCode, err, cleanup)
			d.releaseMultiNICIPByTemplate(multinicTemplate)
		case <-multiNICWaitCh:
			// multiNICWaitCh will close when multi-NIC endpoint is successfully created.
			// this signals the go routine to exit at the synced time.
			return
		}
	}()

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

	// Get the Default Network interface's veth peer ifindex inside the pod ns.
	defaultNetInPodIfIndex, _, err := getPrimaryInterfaceVethPeerIfIndex(podID,
		primaryEp.GetIfIndex(), epTemplate.NetworkNamespace)
	if err != nil {
		return d.errorDuringMultiNICCreation(primaryEp,
			PutEndpointIDInvalidCode, err)
	}

	var eps []*endpoint.Endpoint
	var podIPs networkv1.PodIPsAnnotation
	defaultPodNetworkMTU := d.mtuConfig.GetRouteMTU()
	// parentDevInUse tracks the use of parent device for the L2 interface.
	parentDevInUse := make(map[string]string)
	var interfaceStatusAnnotation networkv1.InterfaceStatusAnnotation
	for _, ref := range interfaceAnnotation {
		skipEpCreation := false
		intfLog := log.WithFields(logrus.Fields{
			logfields.ContainerInterface: ref.InterfaceName,
			logfields.K8sPodName:         podID,
		})
		intfLog.Info("Multinic endpoint request")

		multinicTemplate = epTemplate.DeepCopy()
		multinicTemplate.DatapathConfiguration.DisableSipVerification = disableSourceIPValidation
		multinicTemplate.DatapathConfiguration.EnableMulticast = enableMulticast
		multinicTemplate.DisableLegacyIdentifiers = true
		isDefaultInterface := defaultInterface == ref.InterfaceName

		multinicTemplate.PodStackRedirectIfindex = int64(defaultNetInPodIfIndex)

		// netCR is always set, otherwise we error
		originalIntfCR, netCR, err := d.getInterfaceAndNetworkCR(ctx, &ref, pod)
		if err != nil {
			return d.errorDuringMultiNICCreation(primaryEp, PutEndpointIDInvalidCode, fmt.Errorf("failed getting interface and network CR for pod %q: %v", podID, err))
		}
		intfCR := originalIntfCR.DeepCopy()
		var netParamsRef client.Object
		var isDefaultNetInfcTemp bool
		var skipRouteInstallation bool
		if networkv1.IsDefaultNetwork(netCR.Name) {
			// Update the interface status of the default Network endpoint.
			// When the NetworkInterface is not created for default Network, we create
			// local object, but we do not create it in API
			if intfCR == nil {
				isDefaultNetInfcTemp = true
				intfCR = convertNetworkSpecToInterface(netCR)
			}
			primaryEp.Logger(daemonSubsys).WithField("interfaceCR", intfCR.Name).Debug("Updating interface status")
			intfCR.Status.IpAddresses = nil
			if ipv4 := primaryEp.GetIPv4Address(); ipv4 != "" {
				intfCR.Status.IpAddresses = append(intfCR.Status.IpAddresses, ipv4)
			}
			if ipv6 := primaryEp.GetIPv6Address(); ipv6 != "" {
				intfCR.Status.IpAddresses = append(intfCR.Status.IpAddresses, ipv6)
			}
			intfCR.Status.MacAddress = primaryEp.LXCMac().String()
			intfCR.Status.DNSConfig = netCR.Spec.DNSConfig
			intfCR.Status.Routes = netCR.Spec.Routes
			intfCR.Status.Gateway4 = netCR.Spec.Gateway4

			if netCR.Spec.Gateway4 == nil && netCR.Spec.Type == networkv1.L3NetworkType {
				gw, err := getDefaultNetworkGW(defaultNetInPodIfIndex, epTemplate.NetworkNamespace)
				if err != nil {
					return d.errorWithMultiNICCleanup(primaryEp, PutEndpointIDInvalidCode, fmt.Errorf("failed to get GW for Default Network: %v", err), cleanup)
				}
				if gw == "" {
					primaryEp.Logger(daemonSubsys).WithField("interfaceCR", intfCR.Name).Info("discovered GW is empty")
				} else {
					intfCR.Status.Gateway4 = utilpointer.String(gw)
				}
			}
			intfCR.Status.PodName = utilpointer.String(primaryEp.GetK8sPodName())
		} else if intfCR != nil {
			if netCR.Spec.ParametersRef != nil {
				if netParamsRef, err = d.multinicClient.GetGKENetworkParamSet(ctx, netCR.Spec.ParametersRef); err != nil {
					return d.errorDuringMultiNICCreation(primaryEp, PutEndpointIDInvalidCode, fmt.Errorf("failed getting GKENetworkParamSet CR for pod %q: %v", podID, err))
				}
			}
			if netCR.Spec.Type == networkv1.L2NetworkType {
				// Construct the cleanup function before the interface setup to ensure it can be executed in case of
				// context cancellation or time out. This allows the calling function to handle any necessary
				// cleanup, even if the setup process fails or times out.
				cleanup = connector.ConstructCleanupFunc(ref.InterfaceName, multinicTemplate.NetworkNamespace, podResources, netCR)
				if err = connector.SetupL2Interface(ctx, ref.InterfaceName, pod.Name, podResources, netCR, intfCR, multinicTemplate, d.dhcpClient, d.ipam); err != nil {
					if !reflect.DeepEqual(originalIntfCR.Annotations, intfCR.Annotations) {
						// Patch interface CR annotations via multinicClient
						if err = d.multinicClient.PatchNetworkInterfaceAnnotations(ctx, intfCR); err != nil {
							intfLog.WithError(err).Error("Failed to patch interface CR annotations")
						} else {
							intfLog.Infof("Successfully updated interface CR %+v", intfCR)
						}
					}
					return d.errorWithMultiNICCleanup(primaryEp, PutEndpointIDInvalidCode, fmt.Errorf("failed setting up layer2 interface %q for pod %q: %v", intfCR.Name, podID, err), cleanup)
				}
				// We don't allow different L2 interfaces share the same parent device.
				if name, ok := parentDevInUse[multinicTemplate.ParentDeviceName]; ok {
					return d.errorWithMultiNICCleanup(primaryEp, PutEndpointIDInvalidCode, fmt.Errorf("same parent interface in use by %s and %s for pod %q", ref.InterfaceName, name, podID), cleanup)
				}
				parentDevInUse[multinicTemplate.ParentDeviceName] = ref.InterfaceName

			} else if netCR.Spec.Type == networkv1.L3NetworkType {
				// When L3 network doesn't have GKENetworkParam(GNP) linked
				// and IPAMMode is internal, add a route for the podCIDR on
				// secondary L3 network. This ensures that traffic destined
				// for the secondary network's CIDR is properly routed
				// through the corresponding pod interface.
				var ccc *ipamv1alpha1.ClusterCIDRConfig
				if _, isGNP := netParamsRef.(*networkv1.GKENetworkParamSet); netParamsRef == nil || !isGNP {
					if *netCR.Spec.IPAMMode == networkv1.InternalMode {
						ccc, err = d.multinicClient.GetClusterCIDRConfigForNetwork(ctx, netCR.Name)
						if err != nil {
							return d.errorDuringMultiNICCreation(primaryEp, PutEndpointIDInvalidCode, fmt.Errorf("unable to retrieve ClusterCIDRConfig for network %q: %w", netCR.Name, err))
						}
					}
				}
				if cleanup, err = connector.SetupL3Interface(ref.InterfaceName, pod.Name, podResources, netCR, intfCR, multinicTemplate, d.ipam, netParamsRef, ccc); err != nil {
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

			if d.googleMultiNICEnabled {
				addNetworkLabel(multinicTemplate, intfCR.Spec.NetworkName)
			}

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
				// TODO check if we need to handle v6 for host-interface devices too
				for _, ip := range []netip.Addr{multinicEndpoint.IPv4, multinicEndpoint.IPv6} {
					if ip.IsValid() {
						podIP := networkv1.PodIP{IP: ip.String(), NetworkName: netCR.Name}
						podIPs = append(podIPs, podIP)
					}
				}
			} else {
				// the device typed networks pass out the ip using the multinicTemplate
				podIP := networkv1.PodIP{IP: multinicTemplate.Addressing.IPV4, NetworkName: netCR.Name}
				podIPs = append(podIPs, podIP)
			}
		}

		if intfCR != nil {
			if metadata.IdentityLabels.HasKubevirtVMLabel() || metadata.InfoLabels.HasKubevirtVMLabel() {
				skipRouteInstallation = true
			}
			if err := connector.SetupNetworkRoutes(ref.InterfaceName, intfCR, netCR, multinicTemplate.NetworkNamespace,
				isDefaultInterface, defaultPodNetworkMTU, skipRouteInstallation); err != nil {
				return d.errorWithMultiNICCleanup(primaryEp, PutEndpointIDInvalidCode, fmt.Errorf("failed setting up network %q for pod %q: %v", intfCR.Spec.NetworkName, podID, err), nil)
			}
			intfLog.Infof("Successfully configured network %s", intfCR.Spec.NetworkName)

			// Only patch NetworkInterface when it's referenced in pod annotation
			if ref.Interface != nil {
				// Patch interface CR status via multinicClient
				if err = d.multinicClient.PatchNetworkInterfaceStatus(ctx, intfCR); err != nil {
					return d.errorWithMultiNICCleanup(primaryEp, PutEndpointIDInvalidCode, fmt.Errorf("failed updating status of interface CR %q for pod %q: %v", intfCR.Name, podID, err), nil)
				}
				// Patch interface CR annotations via multinicClient
				if err = d.multinicClient.PatchNetworkInterfaceAnnotations(ctx, intfCR); err != nil {
					return d.errorWithMultiNICCleanup(primaryEp, PutEndpointIDInvalidCode, fmt.Errorf("failed updating annotations of interface CR %q for pod %q: %v", intfCR.Name, podID, err), nil)
				}
				intfLog.Infof("Successfully updated interface CR %+v", intfCR)
			}
			if !isDefaultNetInfcTemp {
				interfaceStatusAnnotation = append(interfaceStatusAnnotation, convertNIObjToAnnotation(intfCR))
			}
		}
	}

	podAnno, err := buildPodAnnotation(podIPs, interfaceStatusAnnotation)
	if err != nil {
		return d.errorDuringMultiNICCreation(primaryEp, PutEndpointIDInvalidCode, fmt.Errorf("failed to build annotation for pod %q: %v", podID, err))
	}
	if err = d.multinicClient.PatchPodAnnotation(ctx, pod, podAnno); err != nil {
		return d.errorDuringMultiNICCreation(primaryEp, PutEndpointIDInvalidCode, fmt.Errorf("failed to patch pod annotation for pod %q: %v", podID, err))
	}

	if epTemplate.SyncBuildEndpoint {
		if err := waitForEndpointsFirstRegeneration(ctx,
			d.endpointManager.GetEndpointsByContainerID(primaryEp.GetContainerID())); err != nil {
			return d.errorDuringMultiNICCreation(primaryEp, PutEndpointIDInvalidCode, err)
		}
	}

	metrics.MultiNetworkPodCreation.WithLabelValues(metrics.LabelValueOutcomeSuccess).Inc()
	return eps, PutEndpointIDCreatedCode, nil
}

// getPrimaryInterfaceVethPeerIfIndex takes the Default (pod-network) endpoint and
// returns the Ifindex and interface name inside the pod-ns, for the Link associated
// with the default (pod-network) Network.
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

// getDefaultNetworkGW returns the GW IPv4 for the Default Network interface
// inside the Pod, taken from Pod's ns existing routes.
func getDefaultNetworkGW(inPodIndex int, nsPath string) (string, error) {
	var err error
	var gw string
	// Get routes from the pod namespace
	var routes []netlink.Route
	findRoutes := func(ns.NetNS) error {
		vethPeer, err := netlink.LinkByIndex(inPodIndex)
		if err != nil {
			return err
		}
		routes, err = safenetlink.RouteList(vethPeer, netlink.FAMILY_V4)
		return err
	}
	err = ns.WithNetNSPath(nsPath, findRoutes)
	if err != nil {
		return "", fmt.Errorf("failed to get routes from inside the pod ns: %v", err)
	}

	for _, rt := range routes {
		if rt.Gw == nil {
			// find route that is for the GW IP itself
			// e.g. "192.168.3.253 dev eth0 scope link"
			gw = rt.Dst.IP.String()
			break
		}
	}
	return gw, nil
}

// getInterfaceAndNetworkCR gets interface and network CR by querying multinicClient object.
// does not return intfCR for default Network
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

	// Determine the network name
	if ref.Network != nil {
		networkName = *ref.Network
	} else if ref.Interface != nil {
		intfCR, err = d.getInterfaceCR(ctx, *ref.Interface, pod.Namespace)
		if err != nil {
			return nil, nil, err
		}
		networkName = intfCR.Spec.NetworkName
	}

	// Fetch the network CR based on the name
	netCR, err := d.multinicClient.GetNetwork(ctx, networkName)
	if err != nil {
		return nil, nil, fmt.Errorf("failed getting network CR %s: %v", networkName, err)
	}

	// No further checks for default network
	if networkv1.IsDefaultNetwork(networkName) {
		return intfCR, netCR, nil
	}

	if *netCR.Spec.IPAMMode == networkv1.ExternalMode {
		if ref.Interface == nil {
			return nil, nil, fmt.Errorf("pod must reference to an interface to connect to external IPAM mode network %s", networkName)
		}
		return intfCR, netCR, nil
	}

	// Now we no longer auto-generate interface CR object, still construct it to reduce code changes
	intfCR = constructNetworkInterfaceObject(ctx, networkName, pod)
	return intfCR, netCR, nil
}

// getInterfaceCRForPod fetches the NetworkInterface object for the pod and network.
func (d *Daemon) getInterfaceCRForPod(ctx context.Context, ref networkv1.InterfaceRef, ns, podName string) (*networkv1.NetworkInterface, error) {
	if ref.Interface == nil {
		// There is no auto generated interface object anymore
		return nil, nil
	}
	intfName := *ref.Interface
	intfCR, err := d.getInterfaceCR(ctx, intfName, ns)
	if err != nil {
		return nil, err
	}
	return intfCR, nil
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

	// The errs slice can contain nil errors, so iterate through it and
	// count only the actual errors.
	var nerrs int
	for _, err := range errs {
		if err != nil {
			nerrs++
			scopedLog.WithError(err).Warn("Ignoring error while deleting endpoint")
		}
	}
	return nerrs
}

func (d *Daemon) deleteMultiNICEndpointQuiet(ep *endpoint.Endpoint, conf endpoint.DeleteConfig, podChanged bool) []error {
	errs := d.endpointManager.RemoveEndpoint(ep, conf)
	ifName := ep.GetInterfaceName()
	containerIfName := ep.GetContainerInterfaceName()
	netNS := ep.GetNetNS()
	deviceType := ep.GetDeviceType()
	ep.Logger(daemonSubsys).WithFields(logrus.Fields{
		logfields.Interface:          ifName,
		logfields.ContainerInterface: containerIfName,
		logfields.NetNSName:          netNS,
		logfields.DeviceType:         deviceType,
	}).Info("Revert multinic endpoint setup")

	if ep.ExternalDHCPEnabled() {
		// If pod changed, then the interface lease is now maintained by a different pod. The lease should
		// not released and instead should just expire for this pod.
		d.dhcpClient.Release(context.Background(), ep.GetContainerID(), netNS, containerIfName, podChanged)
	} else {
		if err := d.releaseMultiNICIP(ep); err != nil {
			errs = append(errs, err)
		}
	}
	var err error
	switch deviceType {
	case multinicep.EndpointDeviceMACVTAP:
		err = connector.RevertMacvtapSetup(containerIfName, ifName, netNS)
	case multinicep.EndpointDeviceMACVLAN:
		err = connector.DeleteInterfaceInRemoteNs(containerIfName, netNS)
	case multinicep.EndpointDeviceIPVLAN:
		err = connector.DeleteInterfaceInRemoteNs(containerIfName, netNS)
	case multinicep.EndpointDeviceMultinicVETH:
		err = connector.DeleteInterfaceInRemoteNs(containerIfName, netNS)
	default:
		err = fmt.Errorf("unsupported device type %q", deviceType)
	}
	if err != nil {
		errs = append(errs, err)
	}

	return errs
}

func (d *Daemon) releaseMultiNICIP(ep *endpoint.Endpoint) error {
	d.ipam.MultiNetworkAllocatorMutex.Lock()
	defer d.ipam.MultiNetworkAllocatorMutex.Unlock()
	log.Infof("releasing multi-nic IP %s", ep.IPv4)
	for _, allocator := range d.ipam.MultiNetworkAllocators {
		err := allocator.Release(ep.IPv4.AsSlice(), ipam.PoolDefault())
		if err != nil {
			return err
		}
	}
	return nil
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
	netParamsRef, err := d.multinicClient.GetGKENetworkParamSet(ctx, netCR.Spec.ParametersRef)
	if err != nil {
		return fmt.Errorf("Error getting params object %s for network %s: %v", netCR.Spec.ParametersRef.Name, netCR.Name, err)
	}
	if err := connector.RevertDeviceInterface(ref.InterfaceName, netCR, netns, netParamsRef); err != nil {
		return fmt.Errorf("Error reverting Device network %v: %v", netCR.Name, err)
	}
	return nil
}

// DeleteEndpointsByID deletes all the endpoints for the given id.
// Only called when EnableGoogleMultiNIC is enabled.
func (d *Daemon) DeleteEndpointsByID(ctx context.Context, id string) (int, error) {
	prefix, eid, err := endpointid.Parse(id)
	if err != nil {
		return 0, api.Error(DeleteEndpointIDInvalidCode, err)
	}

	var eps []*endpoint.Endpoint
	switch prefix {
	case endpointid.ContainerIdPrefix:
		eps = d.endpointManager.GetEndpointsByContainerID(eid)
	case endpointid.PodNamePrefix:
		eps = d.endpointManager.GetEndpointsByPodName(eid)
	default:
		return d.DeleteEndpoint(id)
	}
	if len(eps) == 0 {
		return 0, api.New(DeleteEndpointIDNotFoundCode, "endpoints %q not found", id)
	}
	return d.deleteEndpoints(ctx, eps)
}

// DeleteEndpointsByContainerID deletes all the endpoints for the container id.
// Only called when EnableGoogleMultiNIC is enabled.
func (d *Daemon) DeleteEndpointsByContainerID(ctx context.Context, id string) (int, error) {
	eps := d.endpointManager.GetEndpointsByContainerID(id)
	if len(eps) == 0 {
		return 0, api.New(DeleteEndpointNotFoundCode, "endpoints for container %q not found", id)
	}
	return d.deleteEndpoints(ctx, eps)
}

func (d *Daemon) deleteEndpoints(ctx context.Context, eps []*endpoint.Endpoint) (int, error) {
	log.Infof("Deleting %d endpoints in multinic path", len(eps))
	if len(eps) == 0 {
		return 0, errors.New("no endpoints passed")
	}
	podName := eps[0].K8sPodName
	podNS := eps[0].K8sNamespace

	_, metadata, err := d.fetchK8sMetadataForEndpoint(podNS, podName)
	if err != nil {
		log.WithFields(logrus.Fields{
			logfields.K8sPodName: podName,
			"error":              err,
		}).Error("Failed to fetch annotations from pod when deleting multinic endpoints")
	}
	var nerrs int
	var interfaceAnnotation networkv1.InterfaceAnnotation
	ifNameToInterfaceCR := map[string]*networkv1.NetworkInterface{}
	if metadata != nil && len(metadata.Annotations) > 0 {
		_, interfaceAnnotation, err = fetchMultiNICAnnotation(metadata.Annotations)
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

	// The list of endpoints can be modified during iteration, so create a
	// copy of the slice to iterate over.
	epsToDelete := make([]*endpoint.Endpoint, len(eps))
	copy(epsToDelete, eps)

	deleted := make(map[uint16]struct{})
	for _, ep := range epsToDelete {
		if ep == nil {
			log.Errorf("nil endpoint found in endpoint list")
			nerrs++
			continue
		}
		if _, ok := deleted[ep.ID]; ok {
			log.Warningf("duplicate endpoint ID %d in endpoint list, skipping deletion", ep.ID)
			continue
		}
		deleted[ep.ID] = struct{}{}
		log.WithFields(logrus.Fields{
			logfields.IPv4:        ep.GetIPv4Address(),
			logfields.IPv6:        ep.GetIPv6Address(),
			logfields.ContainerID: ep.GetShortContainerID(),
		}).Info("Delete endpoint request")
		if err := endpoint.APICanModify(ep); err != nil {
			return 0, api.Error(DeleteEndpointIDInvalidCode, err)
		}
		if ep.IsMultiNIC() {
			intfCR, ok := ifNameToInterfaceCR[ep.GetContainerInterfaceName()]
			var currentPod string
			if ok && intfCR == nil {
				// There is no interface object and pod should never change
				currentPod = ep.GetK8sPodName()
			}
			// In case we were unable to gather the interface or the podName is not set,
			// we treat it the same as podChanged=true which will mean that the lease will expire. We rather let the lease expire if
			// we do not know whether it is a pod shutdown or not
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
	return nerrs, nil
}

// addNetworkLabel appends a network label to the existing labels in the
// endpoint template. e.g. networking.gke.io/network: vlan-100, networking.gke.io/network: pod-network.
func addNetworkLabel(epTemplate *models.EndpointChangeRequest, network string) {
	log.WithFields(logrus.Fields{
		"addressing":         epTemplate.Addressing,
		logfields.DeviceType: epTemplate.DeviceType,
		"network":            network,
	}).Info("Add multi-network label")
	epTemplate.Labels = append(epTemplate.Labels, labels.GetMultiNICNetworkLabel(network))
}

// cleanupMultiNICDevMap cleans up entries that's not in the endpoint list.
func cleanupMultiNICDevMap(eps []*endpoint.Endpoint) {
	if option.Config.DryMode {
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

// EnsureMultiNICHostEndpoint adds a multinic host endpoint for a given network.
func (d *Daemon) EnsureMultiNICHostEndpoint(restored []*endpoint.Endpoint, network, parentDevice string) (*endpoint.Endpoint, error) {
	if !option.Config.EnableGoogleMultiNICHostFirewall {
		return nil, nil
	}
	// Default node network is managed by the main daemon process.
	if network == identity.DefaultMultiNICNodeNetwork {
		return nil, nil
	}
	// If a reserved identity does not exist, do not create a multi nic endpoint.
	if _, ok := identity.ReservedMultiNICHostIDForLabels(labels.NewReservedMultiNICHostLabels(network)); !ok {
		return nil, nil
	}
	scopedLog := log.WithField("node-network", network)
	scopedLog.Info("Ensuring multi nic host endpoint")
	ep := d.endpointManager.GetMultiNICHostEndpoint(network)
	// If the endpoint already exists, initialize the node labels.
	if ep != nil {
		node.AddMultiNICHostDevice(parentDevice)
		ep.SetParentDevName(parentDevice)
		d.endpointManager.InitEndpointWithNodeLabels(d.ctx, ep)
		scopedLog.WithField(logfields.EndpointID, ep.ID).Info("Multi nic host endpoint labels initialized")
		return ep, nil
	}
	// Check if the endpoint is being regenerated before creating new one.
	for _, ep := range restored {
		if ep.GetNodeNetworkName() == network {
			return nil, fmt.Errorf("wait for multi nic host endpoint for node network %s to be restored, will retry", network)
		}
	}
	scopedLog.Info("Creating multi nic host endpoint")
	var err error
	if ep, err = d.endpointManager.CreateMultiNICHostEndpoint(
		d.ctx, d, d, d.ipcache, d.l7Proxy, d.identityAllocator,
		fmt.Sprintf("create multi nic host endpoint for node network %s", network),
		network, parentDevice,
	); err != nil {
		scopedLog.Errorf("Unable to create multi nic host endpoint: %v", err)
		return nil, err
	}
	node.AddMultiNICHostDevice(parentDevice)
	scopedLog.WithField(logfields.EndpointID, ep.ID).Info("Multi nic host endpoint created")
	return ep, nil
}

// DeleteMultiNICHostEndpoint deletes the multi nic host endpoint for a given
// network.
func (d *Daemon) DeleteMultiNICHostEndpoint(network, parentDevice string) error {
	// Default node network is managed by the main daemon process.
	if network == identity.DefaultMultiNICNodeNetwork {
		return nil
	}
	scopedLog := log.WithFields(logrus.Fields{
		"node-network": network,
	})
	ep := d.endpointManager.GetMultiNICHostEndpoint(network)
	if ep == nil {
		scopedLog.Warnf("Could not find multi nic host endpoint, skipped deletion")
		return nil
	}
	scopedLog = scopedLog.WithField(logfields.EndpointID, ep.ID)
	scopedLog.Info("Deleting multi nic host endpoint")
	errs := d.endpointManager.RemoveEndpoint(ep, endpoint.DeleteConfig{NoIPRelease: true})
	if len(errs) > 0 {
		err := fmt.Errorf("unable to delete multi nic host endpoint: %v", errs)
		scopedLog.Error(err)
		return err
	}
	node.DeleteMultiNICHostDevice(parentDevice)
	return nil
}

func convertNIObjToAnnotation(ni *networkv1.NetworkInterface) networkv1.InterfaceStatus {
	ret := networkv1.InterfaceStatus{
		NetworkName: ni.Spec.NetworkName,
		IPAddresses: slices.Clone(ni.Status.IpAddresses),
		MACAddress:  ni.Status.MacAddress,
		Routes:      slices.Clone(ni.Status.Routes),
		DNSConfig:   ni.Status.DNSConfig.DeepCopy(),
	}
	if ni.Status.Gateway4 != nil {
		tmp := *ni.Status.Gateway4
		ret.Gateway4 = &tmp
	}
	if dhcpServerIP, ok := ni.Annotations[connector.KubevirtDHCPServerIPAnnotationKey]; ok {
		ret.DHCPServerIP = ptr.To(dhcpServerIP)
	}
	return ret
}

func buildPodAnnotation(podIPs networkv1.PodIPsAnnotation, interfaceStatusAnnotation networkv1.InterfaceStatusAnnotation) (map[string]string, error) {
	ret := make(map[string]string)
	anno, err := networkv1.MarshalAnnotation(podIPs)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal pod IP annoation: %v", err)
	}
	ret[networkv1.PodIPsAnnotationKey] = anno
	anno, err = networkv1.MarshalAnnotation(interfaceStatusAnnotation)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal interface-status annoation: %v", err)
	}
	ret[networkv1.InterfaceStatusAnnotationKey] = anno
	return ret, nil
}

func endpointLookup(d *Daemon, id string) *api.APIError {
	if ep, err := d.endpointManager.Lookup(id); err != nil {
		return api.Error(DeleteEndpointIDInvalidCode, err)
	} else if ep == nil {
		return api.New(DeleteEndpointIDNotFoundCode, "endpoint not found")
	} else if err = endpoint.APICanModify(ep); err != nil {
		return api.Error(DeleteEndpointIDInvalidCode, err)
	}
	return nil
}

func multiNicEndpointLookup(d *Daemon, id string) *api.APIError {
	prefix, eid, err := endpointid.Parse(id)
	if err != nil {
		return api.Error(DeleteEndpointIDInvalidCode, err)
	}
	var eps []*endpoint.Endpoint
	switch prefix {
	case endpointid.ContainerIdPrefix:
		eps = d.endpointManager.GetEndpointsByContainerID(eid)
	case endpointid.PodNamePrefix:
		eps = d.endpointManager.GetEndpointsByPodName(eid)
	default:
		return endpointLookup(d, id)
	}

	if len(eps) == 0 {
		return api.New(DeleteEndpointIDNotFoundCode, "endpoints %q not found", id)
	}
	return nil
}
