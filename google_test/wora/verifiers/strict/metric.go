package strict

import (
	"encoding/json"
	"fmt"
	"os/exec"
)

// MetricLabels defines the structure for labels within a Cilium metric entry.
type MetricLabels struct {
	Direction string `json:"direction"`
	Reason    string `json:"reason"`
}

// MetricEntry defines the structure for a single entry in the Cilium metrics list JSON output.
type MetricEntry struct {
	Labels MetricLabels `json:"labels"`
	Name   string       `json:"name"`
	Value  float64      `json:"value"`
}

// GetInfraAccessDeniedDropCount executes `cilium metrics list` inside a specific Cilium agent pod,
// parses the JSON output, and returns the value of "cilium_drop_count_total"
// where the reason is "Infra access denied".
func GetInfraAccessDeniedDropCount(podName string) (float64, error) {
	targetMetricName := "cilium_drop_count_total"
	targetReason := "Infra access denied"

	cmd := exec.Command(
		"kubectl", "exec", podName, "-n", "kube-system", "-c", "cilium-agent",
		"--", "cilium", "metrics", "list", "-o", "json",
	)

	output, err := cmd.CombinedOutput()
	if err != nil {
		return 0, fmt.Errorf("failed to execute curl command: %v, output: %s", err, string(output))
	}

	var metrics []MetricEntry
	err = json.Unmarshal(output, &metrics)
	if err != nil {
		return 0, fmt.Errorf("failed to unmarshal metrics JSON: %w", err)
	}

	// Find the specific metric and reason
	for _, metric := range metrics {
		if metric.Name == targetMetricName && metric.Labels.Reason == targetReason {
			return metric.Value, nil
		}
	}

	return 0, nil
}
