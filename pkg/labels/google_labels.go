package labels

const (
	// MultinicNetwork is the name of network where the multinic endpoint is in.
	MultinicNetwork = "networking.gke.io/network"
)

// MergeMultiNICLabels merges multinic labels from into to.
// It filters out non-multinic lables and overwrites the values with the same
// multinic labels keys as from into to.
// Example:
// to := Labels{Label{MultinicNetwork, value1, source1}}
// from := Labels{Label{key2, value2, source2}, Label{MultinicNetwork, value3, source3}}
// to.MergeMultiNICLabels(from)
// to will be
//
//	Labels{Label{MultinicNetwork, value3, source3}}
func (l Labels) MergeMultiNICLabels(from Labels) {
	if v, ok := from[MultinicNetwork]; ok {
		l[MultinicNetwork] = v
	}
}

// GetMultiNICNetworkLabel generates the string representation of a multinic label with
// the provided value in the format "k8s:networking.gke.io/network=value".
func GetMultiNICNetworkLabel(v string) string {
	return generateLabelString(LabelSourceK8s, MultinicNetwork, v)
}
