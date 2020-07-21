/*
Copyright 2020 Google LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package agent

import (
	"encoding/json"
	"fmt"
	"strconv"

	"gke-internal/gke-node-firewall/pkg/apis/nodenetworkpolicy/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"

	"github.com/cilium/cilium/pkg/gke/nodefirewall/logging"
	ciliumutils "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/utils"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/policy/api"
)

// objToNodeNetworkPolicy returns policy resource for given object after sanitization.
// This also returns a boolean to specifies if returned resource is valid.
func objToNodeNetworkPolicy(obj interface{}) (*v1alpha1.NodeNetworkPolicy, bool) {
	policy, ok := obj.(*v1alpha1.NodeNetworkPolicy)
	if ok {
		return policy, ok
	}

	// Trying to retrieve the policy from the deleted object.
	tombstone, ok := obj.(*cache.DeletedFinalStateUnknown)
	if !ok {
		logging.NodeFWLogger.Errorf("Error casting obj %v as cache.DeletedFinalStateUnknown", obj)
		return nil, false
	}

	logging.NodeFWLogger.Info("Using DeletedFinalStateUnknown object to retrieve Policy")
	policy, ok = tombstone.Obj.(*v1alpha1.NodeNetworkPolicy)
	if !ok {
		logging.NodeFWLogger.Errorf("Error casting object %v as v1alpha1.NodeNetworkPolicy", obj)
	}

	return policy, ok
}

const (
	resourceTypeNodeNetworkPolicy = "NodeNetworkPolicy"
	// This needs to be sync with gke-internal/gke-node-firewall/pkg/basepolicy/generator/policy.go.
	baseNodeToNodePolicyName = "base-allow-node"
)

func nnpToCiliumPolicyRules(policy *v1alpha1.NodeNetworkPolicy) (api.Rules, error) {
	if policy == nil {
		return nil, fmt.Errorf("cannot parse NodeNetworkPolicy because it is nil")
	}

	// parse ingress rules from the policy.
	ingresses := nnpToCiliumIngressRules(policy)

	// Convert node selector to slim node selector.
	slimSelector, err := slimLabelSelector(policy.Spec.NodeSelector)
	if err != nil {
		return nil, err
	}
	nodeSelector := api.NewESFromK8sLabelSelector("", slimSelector)

	// Construct policy labels.
	policyLabels := getPolicyLabels(policy.Name)

	rule := api.NewRule().
		WithLabels(policyLabels).
		WithIngressRules(ingresses)
	rule.NodeSelector = nodeSelector

	if err := rule.Sanitize(); err != nil {
		return nil, err
	}

	return api.Rules{rule}, nil
}

func nnpToCiliumIngressRules(policy *v1alpha1.NodeNetworkPolicy) []api.IngressRule {
	// Handles a special case which replaces the node network policy that allows
	// traffic between cluster nodes with a policy that allows traffic between
	// all cluster entities.
	if policy.Name == baseNodeToNodePolicyName {
		return []api.IngressRule{
			{FromEntities: api.EntitySlice{api.EntityCluster}},
		}
	}

	ingresses := []api.IngressRule{}
	for _, iRule := range policy.Spec.Ingress {
		var fromRules []api.IngressRule
		if iRule.From != nil && len(iRule.From) > 0 {
			for _, rule := range iRule.From {
				ingress := api.IngressRule{}

				// Parse CIDR-based parts of rule.
				if rule.IPBlock != nil {
					ingress.FromCIDRSet = []api.CIDRRule{ipBlockToCIDRRule(rule.IPBlock)}
				}
				fromRules = append(fromRules, ingress)
			}
		} else {
			// If `From` field is empty or missing, this rule matches all
			// sources (traffic not restricted by source).
			ingress := api.IngressRule{
				FromEndpoints: []api.EndpointSelector{api.WildcardEndpointSelector},
			}

			fromRules = append(fromRules, ingress)
		}

		// Parse the ports and add them to all rules generated from the From section.
		if iRule.Ports != nil && len(iRule.Ports) > 0 {
			toPorts := parsePorts(iRule.Ports)
			for i := range fromRules {
				fromRules[i].ToPorts = toPorts
			}
		}

		ingresses = append(ingresses, fromRules...)
	}
	return ingresses
}

func ipBlockToCIDRRule(block *v1alpha1.IPBlock) api.CIDRRule {
	cidrRule := api.CIDRRule{}
	cidrRule.Cidr = api.CIDR(block.CIDR)
	for _, v := range block.Except {
		cidrRule.ExceptCIDRs = append(cidrRule.ExceptCIDRs, api.CIDR(v))
	}
	return cidrRule
}

func parsePorts(ports []v1alpha1.NodeNetworkPolicyPort) []api.PortRule {
	portRules := []api.PortRule{}
	for _, port := range ports {
		if port.Protocol == nil && port.Port == nil {
			continue
		}

		// Protocol defaults to TCP if not specified.
		protocol := api.ProtoTCP
		if port.Protocol != nil {
			protocol, _ = api.ParseL4Proto(string(*port.Protocol))
		}
		portStr := ""
		if port.Port != nil {
			portStr = strconv.Itoa(int(*port.Port))
		}

		portRule := api.PortRule{
			Ports: []api.PortProtocol{
				{Port: portStr, Protocol: protocol},
			},
		}
		portRules = append(portRules, portRule)
	}

	return portRules
}

func slimLabelSelector(selector metav1.LabelSelector) (*slim_metav1.LabelSelector, error) {
	marshalledSelector, err := json.Marshal(selector)
	if err != nil {
		return nil, err
	}
	slimSelector := &slim_metav1.LabelSelector{}
	if err := json.Unmarshal(marshalledSelector, slimSelector); err != nil {
		return nil, err
	}
	return slimSelector, nil
}

func getPolicyLabels(policyName string) labels.LabelArray {
	return ciliumutils.GetPolicyLabels("", policyName, "", resourceTypeNodeNetworkPolicy)
}
