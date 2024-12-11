package node

import (
	"github.com/cilium/cilium/pkg/lock"
)

var (
	annotations   map[string]string
	annotationsMu lock.RWMutex
)

func SetAnnotations(ann map[string]string) {
	annotationsMu.Lock()
	defer annotationsMu.Unlock()
	annotations = ann
}

func GetAnnotations() map[string]string {
	annotationsMu.RLock()
	defer annotationsMu.RUnlock()
	return annotations
}
