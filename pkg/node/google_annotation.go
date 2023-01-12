package node

import (
	"github.com/cilium/cilium/pkg/lock"
)

var (
	annotations   map[string]string
	annotationsMu lock.RWMutex
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
