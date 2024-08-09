package labels

import (
	"errors"
	"fmt"

	networkv1 "k8s.io/cloud-provider-gcp/crd/apis/network/v1"
)

const (
	// MultinicNetwork is the name of network where the multinic endpoint is in.
	MultinicNetwork = "networking.gke.io/network"

	// IDNameMultiNICHost is a label key used for reserved multi nic host
	// identities.
	IDNameMultiNICHost = "multinic-host"
)

// MergeMultiNICLabels merges multinic labels from into to.
// It filters out non-multinic lables and overwrites the values with the same
// multinic labels keys as from into to.
// Example:
// to := Labels{Label{MultinicNetwork, value1, source1}}
// from := Labels{Label{key2, value2, source2}, Label{MultinicNetwork, value3, source3}}
// to.MergeMultiNICLabels(from)
// to will be: Labels{Label{MultinicNetwork, value3, source3}}
func (l Labels) MergeMultiNICLabels(from Labels) {
	if v, ok := from[MultinicNetwork]; ok {
		// Override the value for MultinicNetwork for default network to the
		// new `default` value from `pod-network` until all the clusters are
		// upgraded defaulted to the `default` value.
		if v.Value == networkv1.DefaultNetworkName {
			v.Value = networkv1.DefaultPodNetworkName
		}
		l[MultinicNetwork] = v
	}
}

// GetMultiNICNetworkLabel generates the string representation of a multinic label with
// the provided value in the format "k8s:networking.gke.io/network=value".
func GetMultiNICNetworkLabel(v string) string {
	return generateLabelString(LabelSourceK8s, MultinicNetwork, v)
}

// FetchMultiNICAnnotation returns the default interface name and interface annotation from the provided
// annotations. The function also verifies the default interface must be specified and referenced in
// the interface annotation. Otherwise, an error is returned.
func FetchMultiNICAnnotation(annotations map[string]string) (string, networkv1.InterfaceAnnotation, error) {
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

// NewReservedMultiNICHostLabels return the reserved multi nic host labels
// for given node network. e.g. "reserved:multinic-host=node-network1"
func NewReservedMultiNICHostLabels(nodeNetwork string) Labels {
	return Labels{IDNameMultiNICHost: NewLabel(IDNameMultiNICHost, nodeNetwork, LabelSourceReserved)}
}

func (l *Labels) HasKubevirtVMLabel() bool {
	if l == nil {
		return false
	}
	_, exist := l.K8sStringMap()["kubevirt/vm"]
	return exist
}
