package cmd

import (
	"context"
	"errors"
	"fmt"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/datapath/connector"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/endpoint/regeneration"
	multinicv1alpha1 "github.com/cilium/cilium/pkg/gke/apis/multinic/v1alpha1"
	multinicannotation "github.com/cilium/cilium/pkg/gke/multinic/annotation"
	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/sirupsen/logrus"
	utilpointer "k8s.io/utils/pointer"

	. "github.com/cilium/cilium/api/v1/server/restapi/endpoint"
)

// errorDuringMultiNICCreation deletes all exposed multinic endpoints when an error occurs during creation.
func (d *Daemon) errorDuringMultiNICCreation(primaryEp *endpoint.Endpoint, code int, err error) ([]*endpoint.Endpoint, int, error) {
	eps := d.endpointManager.LookupEndpointsByContainerID(primaryEp.GetContainerID())
	for _, e := range eps {
		var errs []error
		if e.IsMultiNIC() {
			errs = d.deleteEndpointQuiet(e, endpoint.DeleteConfig{
				// For multinic endpoints, the IPAM is external so no need to release IP.
				NoIPRelease: true,
			})
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
	return nil, code, err
}

// createMultiNICEndpoints attempts to create the multinic endpoints corresponding to
// the provided endpoint change request and primary endpoint (assume it's already created).
func (d *Daemon) createMultiNICEndpoints(ctx context.Context, owner regeneration.Owner, primaryEpTemplate *models.EndpointChangeRequest, primaryEp *endpoint.Endpoint) ([]*endpoint.Endpoint, int, error) {
	epTemplate := primaryEpTemplate.DeepCopy()
	// Reset parameters from the primary endpoint template.
	epTemplate.ID = 0
	epTemplate.Addressing.IPV4ExpirationUUID = ""
	epTemplate.Addressing.IPV6ExpirationUUID = ""
	epTemplate.InterfaceNameInPod = ""
	epTemplate.DatapathConfiguration = &models.EndpointDatapathConfiguration{
		// Disable routing and enable arp passthrough for L2 support.
		RequireArpPassthrough: true,
		RequireRouting:        utilpointer.BoolPtr(false),
		// Set ExternalIpam to true will skip the IP releasing when deleting the endpoint.
		ExternalIpam: true,
	}
	epTemplate.SyncBuildEndpoint = true

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

	multinicAnnotation, ok := annotations[multinicannotation.InterfaceAnnotationKey]
	if !ok {
		log.Debugf("Multinic annotation is not found for pod %q, expect this is not a multinic pod", podID)
		return nil, PutEndpointIDCreatedCode, nil
	}

	interfaceAnnotation, err := multinicannotation.ParseAnnotation(multinicAnnotation)
	if err != nil {
		return d.errorDuringMultiNICCreation(primaryEp, PutEndpointIDInvalidCode, fmt.Errorf("failed parsing multinic annotation for pod %q: %v", podID, err))
	}

	log.WithFields(logrus.Fields{
		logfields.ContainerID: primaryEp.GetContainerID(),
		logfields.EndpointID:  primaryEp.StringID(),
		logfields.K8sPodName:  podID,
		"multinic annotation": multinicAnnotation,
	}).Info("Create multinic endpoint requests with primary endpoint")

	podResources, err := d.kubeletClient.GetPodResources(ctx, pod)
	if err != nil {
		return d.errorDuringMultiNICCreation(primaryEp, PutEndpointIDInvalidCode, fmt.Errorf("failed querying pod resources: %v", err))
	}

	var eps []*endpoint.Endpoint
	for _, ref := range interfaceAnnotation {
		log.WithField(logfields.InterfaceInPod, ref.InterfaceName).Info("Multinic endpoint request")

		if ref.Network != nil && *ref.Network == multinicv1alpha1.DefaultNetworkName {
			log.Debug("Skip the default pod network configuration")
			continue
		}

		multinicTemplate := epTemplate.DeepCopy()
		multinicTemplate.DeviceType = endpoint.EndpointDeviceMACVTAP

		intfCR, netCR, err := d.getInterfaceAndNetworkCR(ref, pod.Namespace)
		if err != nil {
			return d.errorDuringMultiNICCreation(primaryEp, PutEndpointIDInvalidCode, fmt.Errorf("failed getting interface and network CR for pod %q: %v", podID, err))
		}
		// Update the interface status of the primary endpoint if the interface CR exists
		if netCR == nil && intfCR != nil {
			primaryEp.Logger(daemonSubsys).WithField("interfaceCR", intfCR.Name).Debug("Updating interface status")
			intfCR.Status.IpAddresses = nil
			if ipv4 := primaryEp.GetIPv4Address(); ipv4 != "" {
				intfCR.Status.IpAddresses = append(intfCR.Status.IpAddresses, ipv4)
			}
			if ipv6 := primaryEp.GetIPv6Address(); ipv6 != "" {
				intfCR.Status.IpAddresses = append(intfCR.Status.IpAddresses, ipv6)
			}
			intfCR.Status.MacAddress = primaryEp.LXCMac().String()
		} else {
			if netCR.Spec.Type != multinicv1alpha1.L2NetworkType {
				return d.errorDuringMultiNICCreation(primaryEp, PutEndpointIDInvalidCode, fmt.Errorf("invalid network type %v of the multinic endpoint for pod %q", netCR.Spec.Type, podID))
			}

			if netCR.Spec.NodeInterfaceMatcher.InterfaceName != nil {
				// MACVLAN doesn't require pre-allocated pod resources
				// TODO(yfshen): add implementation for MACVLAN
				if !connector.HasMacvtapDevices(*netCR.Spec.NodeInterfaceMatcher.InterfaceName, podResources) {
					return d.errorDuringMultiNICCreation(primaryEp, PutEndpointIDInvalidCode, fmt.Errorf("macvlan is not supported for pod %q", podID))
				}
			}

			if err := connector.SetupMacvtapChild(ref.InterfaceName, podResources, netCR, intfCR, multinicTemplate); err != nil {
				return d.errorDuringMultiNICCreation(primaryEp, PutEndpointIDInvalidCode, fmt.Errorf("failed setting up macvtap child interface for pod %q: %v", podID, err))
			}

			// Append multinic labels for the interface and network
			multinicTemplate.Labels = append(multinicTemplate.Labels, labels.GetMultiNICInterfaceLabel(ref.InterfaceName), labels.GetMultiNICNetworkLabel(intfCR.Spec.NetworkName))
			multinicEndpoint, code, err := d.createEndpoint(ctx, owner, multinicTemplate)
			if err != nil {
				return d.errorDuringMultiNICCreation(primaryEp, code, fmt.Errorf("failed creating multinic endpoint for pod %q with code %d: %v", podID, code, err))
			}

			log.WithField(logfields.EndpointID, multinicEndpoint.StringID()).Info("Successful multinic endpoint request")

			eps = append(eps, multinicEndpoint)
		}

		// Update interface CR via multinicClient
		intfCR, err = d.multinicClient.UpdateNetworkInterfaceStatus(ctx, intfCR)
		if err != nil {
			return d.errorDuringMultiNICCreation(primaryEp, PutEndpointIDInvalidCode, fmt.Errorf("failed updating interface CR %q for pod %q: %v", intfCR.Name, podID, err))
		}
		log.Debugf("Successfully update interface CR %+v", intfCR)
	}

	return eps, PutEndpointIDCreatedCode, nil
}

// getInterfaceAndNetworkCR gets interface and network CR by querying multinicClient object.
func (d *Daemon) getInterfaceAndNetworkCR(ref multinicannotation.InterfaceRef, ns string) (*multinicv1alpha1.NetworkInterface, *multinicv1alpha1.Network, error) {
	if ref.Interface == nil && ref.Network == nil {
		return nil, nil, fmt.Errorf("both interface and network name are not set for the interface %q", ref.InterfaceName)
	}
	if ref.Interface != nil && ref.Network != nil {
		return nil, nil, fmt.Errorf("one and only one of interface or network name can be set for the interface %q", ref.InterfaceName)
	}

	if ref.Network != nil {
		// TODO(yfshen): support non-staic case for multinic interface
		return nil, nil, fmt.Errorf("interface CR needs to be specified for the interface %q, only static configuration is supported for now", ref.InterfaceName)
	}

	intfCR, err := d.multinicClient.GetNetworkInterface(*ref.Interface, ns)
	if err != nil {
		return nil, nil, fmt.Errorf("failed getting interface CR %s/%s: %v", ns, *ref.Interface, err)
	}
	if intfCR.Spec.NetworkName == multinicv1alpha1.DefaultNetworkName {
		// Directly return the interface CR when it points to the default network
		return intfCR, nil, nil
	}
	netCR, err := d.multinicClient.GetNetwork(intfCR.Spec.NetworkName)
	if err != nil {
		return nil, nil, fmt.Errorf("failed getting network CR %s: %v", intfCR.Spec.NetworkName, err)
	}
	return intfCR, netCR, nil
}
