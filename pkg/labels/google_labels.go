package labels

const (
	// multinicNetwork is the name of network where the multinic endpoint is in.
	multinicNetwork = "anthos.io.multinic.network"

	// multinicInterface is the name of interface which the multinic endpoint represents for.
	multinicInterface = "anthos.io.multinic.interface"
)

// MergeMultiNICLabels merges multinic labels from into to.
// It filters out non-multinic lables and overwrites the values with the same
// multinic labels keys as from into to.
// Example:
// to := Labels{Label{multinicNetwork, value1, source1}}
// from := Labels{Label{key2, value2, source2}, Label{multinicNetwork, value3, source3}}
// to.MergeMultiNICLabels(from)
// to will be
//   Labels{Label{multinicNetwork, value3, source3}}
func (l Labels) MergeMultiNICLabels(from Labels) {
	if v, ok := from[multinicNetwork]; ok {
		l[multinicNetwork] = v
	}
	if v, ok := from[multinicInterface]; ok {
		l[multinicInterface] = v
	}
}

// GetMultiNICNetworkLabel generates the string representation of a multinic label with
// the provided value in the format "k8s:io.cilium.k8s.multinic.network=value".
func GetMultiNICNetworkLabel(v string) string {
	return generateLabelString(LabelSourceK8s, multinicNetwork, v)
}

// GetMultiNICInterfaceLabel generates the string representation of a label with
// the provided value in the format "k8s:io.cilium.k8s.multinic.interface=value".
func GetMultiNICInterfaceLabel(v string) string {
	return generateLabelString(LabelSourceK8s, multinicInterface, v)
}
