// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

// THE FILE IS MODIFIED FROM ISOVALENT hubble-flow-policy-metadata PLUGIN.
package policylogger

import (
	"errors"
	"net"

	"github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/pkg/hubble/parser/getters"
	"github.com/cilium/cilium/pkg/identity"
	k8sConst "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/monitor/api"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/policy/trafficdirection"
	"github.com/cilium/cilium/pkg/source"
	"github.com/cilium/cilium/pkg/u8proto"
	"github.com/sirupsen/logrus"
)

type endpointPolicyGetter interface {
	GetRealizedPolicyRuleLabelsForKey(key policy.Key) (derivedFrom labels.LabelArrayList, revision uint64, ok bool)
}

type policyCorrelator interface {
	correlatePolicy(f *flow.Flow) ([]*Policy, error)
}

type policyCorrelation struct {
	endpointGetter getters.EndpointGetter
}

func extractFlowKey(f *flow.Flow) (
	direction trafficdirection.TrafficDirection,
	endpointIP net.IP,
	remoteIdentity identity.NumericIdentity,
	proto u8proto.U8proto,
	dport uint16,
) {
	switch f.GetTrafficDirection() {
	case flow.TrafficDirection_EGRESS:
		direction = trafficdirection.Egress
		endpointIP = net.ParseIP(f.GetIP().GetSource())
		remoteIdentity = identity.NumericIdentity(f.GetDestination().GetIdentity())
	case flow.TrafficDirection_INGRESS:
		direction = trafficdirection.Ingress
		endpointIP = net.ParseIP(f.GetIP().GetDestination())
		remoteIdentity = identity.NumericIdentity(f.GetSource().GetIdentity())
	default:
		direction = trafficdirection.Invalid
		endpointIP = net.IPv4zero
		remoteIdentity = identity.IdentityUnknown
	}

	if tcp := f.GetL4().GetTCP(); tcp != nil {
		proto = u8proto.TCP
		dport = uint16(tcp.GetDestinationPort())
	} else if udp := f.GetL4().GetUDP(); udp != nil {
		proto = u8proto.UDP
		dport = uint16(udp.GetDestinationPort())
	} else {
		proto = u8proto.ANY
		dport = 0
	}

	return
}

// lookupPoliciesForKey retrives the policy rule label sets for specified
// policy key and returns a slice of k8s policy resources associated with those
// label sets.
func lookupPoliciesForKey(ep endpointPolicyGetter, key policy.Key) []*Policy {
	var policyRuleLabelSets labels.LabelArrayList
	// Check for L4 policy rules
	derivedFromRules, _, ok := ep.GetRealizedPolicyRuleLabelsForKey(key)
	if ok {
		policyRuleLabelSets = append(policyRuleLabelSets, derivedFromRules...)
	}

	// Check for L3 policy rules
	//
	// Consider the network policy:
	// spec:
	//  podSelector: {}
	//  ingress:
	//  - from:
	//    - podSelector:
	//        app: frontend
	//
	// This policy allows all ingress traffic from the identity of the pods
	// with labels {app: frontend}
	derivedFromRules, _, ok = ep.GetRealizedPolicyRuleLabelsForKey(policy.Key{
		Identity:         key.Identity,
		DestPort:         0,
		Nexthdr:          0,
		TrafficDirection: key.TrafficDirection,
	})
	if ok {
		policyRuleLabelSets = append(policyRuleLabelSets, derivedFromRules...)
	}

	// Check for allow-specific-port-protocol policies.
	// This covers the case where one or more identities are allowed by network policy.
	//
	// Consider the network policy:
	// spec:
	//  podSelector: {}
	//  ingress:
	//  - ports:
	//    - port: 80
	//      protocol: TCP
	//
	// The policy applies to ingress TCP traffic on port 80 from all the remote
	// pods/ identities.
	derivedFromRules, _, ok = ep.GetRealizedPolicyRuleLabelsForKey(policy.Key{
		Identity:         0,
		DestPort:         key.DestPort,
		Nexthdr:          key.Nexthdr,
		TrafficDirection: key.TrafficDirection,
	})
	if ok {
		policyRuleLabelSets = append(policyRuleLabelSets, derivedFromRules...)
	}

	// Check for allow-specific-protocol policy rules.
	//
	// Consider the network policy:
	// spec:
	//  podSelector: {}
	//  ingress:
	//  - ports:
	//    - protocol: TCP
	//
	// The policy applies to ingress TCP traffic from all the remote pods/ identities.
	if key.DestPort != 0 {
		derivedFromRules, _, ok = ep.GetRealizedPolicyRuleLabelsForKey(policy.Key{
			Identity:         0,
			DestPort:         0,
			Nexthdr:          key.Nexthdr,
			TrafficDirection: key.TrafficDirection,
		})
		if ok {
			policyRuleLabelSets = append(policyRuleLabelSets, derivedFromRules...)
		}
	}

	// Check for allow-all policy rules
	//
	// Consider the network policy:
	// spec:
	//  podSelector: {}
	//  ingress: {}
	//
	// The policy applies to ingress traffic from all the remote pods/ identities.
	derivedFromRules, _, ok = ep.GetRealizedPolicyRuleLabelsForKey(policy.Key{
		Identity:         0,
		DestPort:         0,
		Nexthdr:          0,
		TrafficDirection: key.TrafficDirection,
	})
	if ok {
		policyRuleLabelSets = append(policyRuleLabelSets, derivedFromRules...)
	}

	policyMap := make(map[Policy]bool, len(policyRuleLabelSets))
	var policies []*Policy

	for _, labelSet := range policyRuleLabelSets {
		policy, ok := k8sResourceForPolicyLabelSet(labelSet)
		if !ok {
			log.WithField(logfields.Labels, labelSet).
				Debug("unable to find a k8s policy resource for policy rule label set")
			continue
		}
		// Skip duplicates policies.
		if policyMap[policy] {
			continue
		}
		policyMap[policy] = true
		policies = append(policies, &policy)
	}

	return policies
}

// k8sResourceForPolicyLabelSet converts a given policy rule label set into
// a k8s policy resource (e.g. NetworkPolicy, CiliumNetworkPolicy)
func k8sResourceForPolicyLabelSet(labelSet labels.LabelArray) (Policy, bool) {
	var kind, ns, name string
	for _, l := range labelSet {
		if l.Source != string(source.Kubernetes) {
			continue
		}
		switch l.Key {
		case k8sConst.PolicyLabelName:
			name = l.Value
		case k8sConst.PolicyLabelNamespace:
			ns = l.Value
		case k8sConst.PolicyLabelDerivedFrom:
			kind = l.Value
		}

		if kind != "" && name != "" && ns != "" {
			return Policy{Kind: kind, Namespace: ns, Name: name}, true
		}
	}
	return Policy{}, false
}

func (p *policyCorrelation) correlatePolicy(f *flow.Flow) ([]*Policy, error) {
	if f.GetEventType().GetType() != int32(api.MessageTypePolicyVerdict) ||
		f.GetVerdict() != flow.Verdict_FORWARDED {
		// we are only interested in policy verdict notifications for forwarded flows
		return nil, nil
	}

	// extract fields relevant for looking up the policy
	direction, endpointIP, remoteIdentity, proto, dport := extractFlowKey(f)

	// obtain reference to endpoint on which the policy verdict was taken
	epInfo, ok := p.endpointGetter.GetEndpointInfo(endpointIP)
	if !ok {
		log.WithField(logfields.IPAddr, endpointIP).
			Warn("dropping policy verdict notification for unknown endpoint")
		return nil, nil
	}
	ep, ok := epInfo.(endpointPolicyGetter)
	if !ok {
		log.WithField(logfields.IPAddr, endpointIP).
			Warn("endpoint does not implement GetRealizedPolicyRuleLabelsForKey")
		return nil, errors.New("unsupported cilium version")
	}

	policies := lookupPoliciesForKey(ep, policy.Key{
		Identity:         uint32(remoteIdentity),
		DestPort:         dport,
		Nexthdr:          uint8(proto),
		TrafficDirection: uint8(direction),
	})
	if len(policies) <= 0 {
		log.WithFields(logrus.Fields{
			logfields.Identity:         remoteIdentity,
			logfields.Port:             dport,
			logfields.Protocol:         proto,
			logfields.TrafficDirection: direction,
		}).Debug("unable to find policy for policy verdict event")
		return nil, nil
	}

	return policies, nil
}
