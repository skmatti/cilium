// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package utils

import "github.com/cilium/cilium/pkg/option"

func updateSystemLabels(labels map[string]string) {
	for k, v := range option.Config.EndpointSystemLabels {
		labels[k] = v
	}
}

func removeSystemLabels(labels map[string]string) {
	for k := range option.Config.EndpointSystemLabels {
		delete(labels, k)
	}
}
