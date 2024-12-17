package node

import (
	"github.com/cilium/cilium/pkg/cidr"
	"github.com/cilium/cilium/pkg/lock"
)

var (
	annotations   map[string]string
	annotationsMu lock.RWMutex
	podNetworks   map[string]*cidr.CIDR
	podNetworksMu lock.RWMutex
)

// SetAnnotations sets the global node annotations map.
// This map should be regularly updated everytime there is a change in node annotations.
func SetAnnotations(ann map[string]string) {
	annotationsMu.Lock()
	defer annotationsMu.Unlock()
	annotations = ann
}

// GetAnnotations returns the global node annotations map.
func GetAnnotations() map[string]string {
	annotationsMu.RLock()
	defer annotationsMu.RUnlock()
	return annotations
}

// SetPodNetworks sets the map that contains pod networks on the node.
// This map should be regularly updated everytime there is a change in node annotations.
func SetPodNetworks(nws map[string]*cidr.CIDR) {
	podNetworksMu.Lock()
	defer podNetworksMu.Unlock()
	podNetworks = nws
}

// GetPodNetworks returns the existing pod networks supported on the node.
func GetPodNetworks() map[string]*cidr.CIDR {
	podNetworksMu.RLock()
	defer podNetworksMu.RUnlock()
	return podNetworks
}
