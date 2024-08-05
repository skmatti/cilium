package controller

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/cilium/cilium/pkg/k8s/types"
	"github.com/cilium/cilium/pkg/labels"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sLabels "k8s.io/apimachinery/pkg/labels"
)

func generateLabelSelectors(labelSelectorStrs []string) ([]*metav1.LabelSelector, error) {
	var res []*metav1.LabelSelector
	for _, labelSelectorStr := range labelSelectorStrs {
		labelSelectorStr = strings.TrimSpace(labelSelectorStr)
		if labelSelectorStr == "" {
			// Skip empty label selector
			continue
		}
		labelSelector, err := metav1.ParseToLabelSelector(labelSelectorStr)
		if err != nil {
			return nil, fmt.Errorf("parse label selector %q: %w", labelSelectorStr, err)
		}
		res = append(res, labelSelector)
	}
	if len(res) == 0 {
		return nil, fmt.Errorf("at least one label selector is required")
	}
	return res, nil
}

func convertLabelArrayToK8SLabelSet(labelArray labels.LabelArray) k8sLabels.Set {
	// Note we are only going to match k8s labels
	labels := labelArray.Labels().GetFromSource("k8s")
	labelsMap := make(map[string]string)
	for _, label := range labels {
		labelsMap[label.Key] = label.Value
	}
	return k8sLabels.Set(labelsMap)
}

func matchesAnyLabelSelectors(labelSelectors []k8sLabels.Selector, labelsSet k8sLabels.Set) bool {
	if len(labelSelectors) == 0 || len(labelsSet) == 0 {
		return false
	}
	for _, selector := range labelSelectors {
		if selector.Matches(labelsSet) {
			return true
		}
	}
	return false
}

// ipsOfCiliumEndpoint returns a list of IPv4 address associated with the given cilium endpoint.
func ipsOfCiliumEndpoint(cep *types.CiliumEndpoint) map[netip.Addr]struct{} {
	if cep == nil {
		return nil
	}
	res := make(map[netip.Addr]struct{})

	if n := cep.Networking; n != nil {
		for _, address := range n.Addressing {
			for _, ipStr := range []string{address.IPV4} {
				if ipStr == "" {
					continue
				}
				addr, err := netip.ParseAddr(ipStr)
				if err != nil || !addr.Is4() {
					continue
				}
				res[addr] = struct{}{}
			}
		}
	}
	return res
}
