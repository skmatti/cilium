// Copyright 2022 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package controller

import (
	"errors"
	"fmt"

	"github.com/cilium/cilium/pkg/gke/apis/fqdnnetworkpolicy/v1alpha1"
	"github.com/cilium/cilium/pkg/gke/util/ciliumconvert"
	k8sCilium "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	k8sCiliumUtils "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/utils"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	k8sUtils "github.com/cilium/cilium/pkg/k8s/utils"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/policy/api"
)

const (
	resourceTypeFQDNNetworkPolicy = "FQDNNetworkPolicy"
)

// dnsProxyRedirect adds an egress rule to proxy traffic sent
// to kube-dns on port 53 through the DNS Proxy.
func dnsProxyRedirect() api.EgressRule {
	kubeDNSSelector := &slim_metav1.LabelSelector{
		MatchLabels: map[string]string{
			k8sCilium.PodNamespaceLabel: "kube-system",
			"k8s-app":                   "kube-dns",
		},
	}
	return api.EgressRule{
		EgressCommonRule: api.EgressCommonRule{
			ToEndpoints: []api.EndpointSelector{
				api.NewESFromK8sLabelSelector(labels.LabelSourceK8sKeyPrefix, kubeDNSSelector),
			},
		},
		ToPorts: []api.PortRule{
			{
				Ports: []api.PortProtocol{
					{
						Port:     "53",
						Protocol: api.ProtoAny,
					},
				},
				Rules: &api.L7Rules{
					DNS: []api.PortRuleDNS{
						{MatchPattern: "*"},
					},
				},
			},
		},
	}
}

// epSelector generates the endpoint selector associated with the provided FQDN
// Network Policy. It combines the PodSelector in the policy with the namespace
// of the policy itself to fully specify the selected endpoints.
func epSelector(fqdn *v1alpha1.FQDNNetworkPolicy) api.EndpointSelector {
	slimSel := ciliumconvert.SlimLabelSelector(fqdn.Spec.PodSelector)
	if slimSel.MatchLabels == nil {
		slimSel.MatchLabels = make(map[string]string)
	}
	slimSel.MatchLabels[k8sCilium.PodNamespaceLabel] = k8sUtils.ExtractNamespaceOrDefault(&fqdn.ObjectMeta)
	return api.NewESFromK8sLabelSelector(labels.LabelSourceK8sKeyPrefix, &slimSel)
}

// policyLabels returns the list of labels used to uniquely identify the FQDN
// Network Policy. This is used when managing the lifecycle of the rules for
// this policy.
func policyLabels(fqdn *v1alpha1.FQDNNetworkPolicy) []labels.Label {
	ns := k8sUtils.ExtractNamespaceOrDefault(&fqdn.ObjectMeta)
	policyName := fqdn.Name
	policyUID := fqdn.UID
	return k8sCiliumUtils.GetPolicyLabels(ns, policyName, policyUID, resourceTypeFQDNNetworkPolicy)
}

// parseFQDNNetworkPolicy converts the FQDNNetworkPolicy object into the
// equivalent Cilium Rule object. The Rule object may then be inject into the
// policy manager.
func parseFQDNNetworkPolicy(fqdn *v1alpha1.FQDNNetworkPolicy) (*api.Rule, error) {
	if fqdn == nil {
		return nil, errors.New("cannot parse nil object")
	}
	egresses := []api.EgressRule{dnsProxyRedirect()}
	for _, egress := range fqdn.Spec.Egress {
		fqdns := make([]api.FQDNSelector, 0, len(egress.Matches))
		for _, sel := range egress.Matches {
			fqdns = append(fqdns, api.FQDNSelector{
				MatchName:    sel.Name,
				MatchPattern: sel.Pattern,
			})
		}
		ports := make([]api.PortProtocol, 0, len(egress.Ports))
		for _, p := range egress.Ports {
			// Port value of "0" is treated as matching all ports. FQDN Network
			// Policy matches all port numbers if the value is unspecified.
			portStr := "0"
			if p.Port != nil {
				portStr = fmt.Sprint(*p.Port)
			}
			protocol, err := api.ParseL4Proto(p.Protocol)
			if err != nil {
				return nil, err
			}
			ports = append(ports, api.PortProtocol{
				Port:     portStr,
				Protocol: protocol,
			})
		}
		rule := api.EgressRule{
			ToFQDNs: fqdns,
		}
		if len(ports) > 0 {
			rule.ToPorts = []api.PortRule{{Ports: ports}}
		}
		egresses = append(egresses, rule)
	}

	rule := api.NewRule().
		WithEgressRules(egresses).
		WithEndpointSelector(epSelector(fqdn)).
		WithLabels(policyLabels(fqdn))

	if err := rule.Sanitize(); err != nil {
		return nil, fmt.Errorf("parse error: %w", err)
	}
	return rule, nil
}
