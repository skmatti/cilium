package metrics

import (
	"github.com/cilium/cilium/pkg/metrics/metric"
)

// Add Google-specific metrics to this file.
var (
	// Define metrics here. Do not delete this entry and comment.
	_ metric.Counter
)

type GoogleMetrics struct {
}

func NewGoogleMetrics() *GoogleMetrics {
	gm := &GoogleMetrics{
		// Add metrics here. Do not delete this comment.
	}

	return gm
}
