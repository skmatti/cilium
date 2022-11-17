//go:build !privileged_tests
// +build !privileged_tests

// Copyright 2020 Google LLC
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

package policylogger

import (
	"fmt"
	"net"
	"testing"

	"github.com/cilium/cilium/api/v1/flow"
	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
	"github.com/cilium/cilium/pkg/hubble/testutils"
	k8sConst "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/monitor/api"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/policy/trafficdirection"
	"github.com/cilium/cilium/pkg/u8proto"
	"github.com/golang/protobuf/ptypes/timestamp"
	"github.com/google/go-cmp/cmp"
)

var (
	testFlow = &flow.Flow{
		Time:    &timestamp.Timestamp{Seconds: 1592083771, Nanos: 445836587},
		Verdict: flow.Verdict_FORWARDED,
		IP: &flow.IP{
			Source:      "10.84.1.7",
			Destination: "10.84.0.11",
			IpVersion:   flow.IPVersion_IPv4,
		},
		L4: &flow.Layer4{Protocol: &flow.Layer4_TCP{
			TCP: &flow.TCP{
				SourcePort:      55644,
				DestinationPort: 8080,
				Flags:           &flow.TCPFlags{SYN: true},
			},
		}},
		Source: &flow.Endpoint{
			Identity:  24583,
			Namespace: "default",
		},
		Destination: &flow.Endpoint{
			ID:       1072,
			Identity: 15292,
		},
		Type:                  flow.FlowType_L3_L4,
		Reply:                 false,
		EventType:             &flow.CiliumEventType{Type: int32(api.MessageTypePolicyVerdict)},
		TrafficDirection:      flow.TrafficDirection_INGRESS,
		PolicyMatchType:       api.PolicyMatchL3L4,
		TraceObservationPoint: flow.TraceObservationPoint_UNKNOWN_POINT,
	}

	endpointMap = map[string]v1.EndpointInfo{
		"10.84.0.11": &testutils.FakeEndpointInfo{
			ID:             1072,
			Identity:       15292,
			PodName:        "pod-10.84.0.11",
			PodNamespace:   "default",
			PolicyRevision: 1,
			PolicyMap: map[policy.Key]labels.LabelArrayList{
				{Identity: 24583, DestPort: 0, Nexthdr: 0, TrafficDirection: trafficdirection.Ingress.Uint8()}: {labels.ParseLabelArray(
					fmt.Sprintf("k8s:%s=allow-all", k8sConst.PolicyLabelName),
					fmt.Sprintf("k8s:%s=default", k8sConst.PolicyLabelNamespace),
					fmt.Sprintf("k8s:%s=NetworkPolicy", k8sConst.PolicyLabelDerivedFrom),
				)},
			},
		},
	}
)

func TestLookUpPoliciesForKey(t *testing.T) {
	const (
		tcp       = uint8(u8proto.TCP)
		udp       = uint8(u8proto.UDP)
		icmp      = uint8(u8proto.ICMP)
		ingress   = uint8(trafficdirection.Ingress)
		egress    = uint8(trafficdirection.Egress)
		identity1 = 1
		identity2 = 2
		port80    = 80
		port81    = 81
	)

	label1 := labels.ParseLabelArray(
		fmt.Sprintf("k8s:%s=NetworkPolicy", k8sConst.PolicyLabelDerivedFrom),
		fmt.Sprintf("k8s:%s=ns1", k8sConst.PolicyLabelNamespace),
		fmt.Sprintf("k8s:%s=foo1", k8sConst.PolicyLabelName))
	label2 := labels.ParseLabelArray(
		fmt.Sprintf("k8s:%s=NetworkPolicy", k8sConst.PolicyLabelDerivedFrom),
		fmt.Sprintf("k8s:%s=ns2", k8sConst.PolicyLabelNamespace),
		fmt.Sprintf("k8s:%s=bar1", k8sConst.PolicyLabelName))
	label3 := labels.ParseLabelArray(
		fmt.Sprintf("k8s:%s=CiliumNetworkPolicy", k8sConst.PolicyLabelDerivedFrom),
		fmt.Sprintf("k8s:%s=ns3", k8sConst.PolicyLabelNamespace),
		fmt.Sprintf("k8s:%s=baz1", k8sConst.PolicyLabelName))

	for _, tc := range []struct {
		desc   string
		ep     *testutils.FakeEndpointInfo
		key    policy.Key
		expect []*Policy
	}{
		{
			desc: "empty policy map and key",
			ep:   &testutils.FakeEndpointInfo{},
		},
		{
			desc: "empty policy map and non-empty key",
			ep:   &testutils.FakeEndpointInfo{},
			key: policy.Key{
				Identity: identity1,
				Nexthdr:  tcp,
			},
		},
		{
			desc: "allow all policy matches",
			ep: &testutils.FakeEndpointInfo{
				PolicyMap: map[policy.Key]labels.LabelArrayList{
					{TrafficDirection: ingress}: {label1},
				},
			},
			key: policy.Key{
				Identity:         identity1,
				Nexthdr:          tcp,
				TrafficDirection: ingress,
			},
			expect: []*Policy{
				{
					Kind:      "NetworkPolicy",
					Namespace: "ns1",
					Name:      "foo1",
				},
			},
		},
		{
			desc: "allow all policy does not match",
			ep: &testutils.FakeEndpointInfo{
				PolicyMap: map[policy.Key]labels.LabelArrayList{
					{TrafficDirection: ingress}: {label1},
				},
			},
			key: policy.Key{
				Identity:         identity1,
				Nexthdr:          tcp,
				TrafficDirection: egress,
			},
		},
		{
			desc: "allow tcp protocol policy matches",
			ep: &testutils.FakeEndpointInfo{
				PolicyMap: map[policy.Key]labels.LabelArrayList{
					{Nexthdr: tcp, TrafficDirection: ingress}: {label1},
				},
			},
			key: policy.Key{
				Identity:         identity1,
				DestPort:         8080,
				Nexthdr:          tcp,
				TrafficDirection: ingress,
			},
			expect: []*Policy{
				{
					Kind:      "NetworkPolicy",
					Namespace: "ns1",
					Name:      "foo1",
				},
			},
		},
		{
			desc: "allow tcp protocol policy does not match",
			ep: &testutils.FakeEndpointInfo{
				PolicyMap: map[policy.Key]labels.LabelArrayList{
					{Nexthdr: tcp, TrafficDirection: ingress}: {label1},
				},
			},
			key: policy.Key{
				Nexthdr:          udp,
				TrafficDirection: ingress,
			},
		},
		{
			desc: "allow tcp port 80 policy matches",
			ep: &testutils.FakeEndpointInfo{
				PolicyMap: map[policy.Key]labels.LabelArrayList{
					{DestPort: port80, Nexthdr: tcp, TrafficDirection: ingress}: {label1},
				},
			},
			key: policy.Key{
				Identity:         identity1,
				DestPort:         port80,
				Nexthdr:          tcp,
				TrafficDirection: ingress,
			},
			expect: []*Policy{
				{
					Kind:      "NetworkPolicy",
					Namespace: "ns1",
					Name:      "foo1",
				},
			},
		},
		{
			desc: "allow tcp port 80 policy does not match",
			ep: &testutils.FakeEndpointInfo{
				PolicyMap: map[policy.Key]labels.LabelArrayList{
					{DestPort: port80, Nexthdr: tcp, TrafficDirection: ingress}: {label1},
				},
			},
			key: policy.Key{
				DestPort:         port81,
				Nexthdr:          tcp,
				TrafficDirection: ingress,
			},
		},
		{
			desc: "allow specific identity policy matches",
			ep: &testutils.FakeEndpointInfo{
				PolicyMap: map[policy.Key]labels.LabelArrayList{
					{Identity: identity2, DestPort: port80, Nexthdr: tcp, TrafficDirection: ingress}: {label1},
				},
			},
			key: policy.Key{
				Identity:         identity2,
				DestPort:         port80,
				Nexthdr:          tcp,
				TrafficDirection: ingress,
			},
			expect: []*Policy{
				{
					Kind:      "NetworkPolicy",
					Namespace: "ns1",
					Name:      "foo1",
				},
			},
		},
		{
			desc: "allow specific identity policy does not match",
			ep: &testutils.FakeEndpointInfo{
				PolicyMap: map[policy.Key]labels.LabelArrayList{
					{Identity: identity1, DestPort: port80, Nexthdr: tcp, TrafficDirection: ingress}: {label1},
				},
			},
			key: policy.Key{
				Identity:         identity2,
				DestPort:         port80,
				Nexthdr:          tcp,
				TrafficDirection: ingress,
			},
		},
		{
			desc: "multiple policies match",
			ep: &testutils.FakeEndpointInfo{
				PolicyMap: map[policy.Key]labels.LabelArrayList{
					{Identity: identity1, DestPort: port80, Nexthdr: tcp, TrafficDirection: ingress}: {label1},
					{Identity: identity1, TrafficDirection: ingress}:                                 {label2},
					{Nexthdr: tcp, TrafficDirection: ingress}:                                        {label3},
				},
			},
			key: policy.Key{
				Identity:         identity1,
				DestPort:         port81,
				Nexthdr:          tcp,
				TrafficDirection: ingress,
			},
			expect: []*Policy{
				{
					Kind:      "NetworkPolicy",
					Namespace: "ns2",
					Name:      "bar1",
				},
				{
					Kind:      "CiliumNetworkPolicy",
					Namespace: "ns3",
					Name:      "baz1",
				},
			},
		},
		{
			desc: "multiple policies match duplicate labels",
			ep: &testutils.FakeEndpointInfo{
				PolicyMap: map[policy.Key]labels.LabelArrayList{
					{Identity: identity1, DestPort: port80, Nexthdr: tcp, TrafficDirection: ingress}: {label1},
					{Identity: identity1, TrafficDirection: ingress}:                                 {label2},
					{Nexthdr: tcp, TrafficDirection: ingress}:                                        {label3},
					{TrafficDirection: ingress}:                                                      {label3},
				},
			},
			key: policy.Key{
				Identity:         identity1,
				DestPort:         port81,
				Nexthdr:          tcp,
				TrafficDirection: ingress,
			},
			expect: []*Policy{
				{
					Kind:      "NetworkPolicy",
					Namespace: "ns2",
					Name:      "bar1",
				},
				{
					Kind:      "CiliumNetworkPolicy",
					Namespace: "ns3",
					Name:      "baz1",
				},
			},
		},
		{
			desc: "multiple policies match for icmp traffic",
			ep: &testutils.FakeEndpointInfo{
				PolicyMap: map[policy.Key]labels.LabelArrayList{
					{Identity: identity1, Nexthdr: tcp, TrafficDirection: ingress}: {label1},
					{Identity: identity1, TrafficDirection: ingress}:               {label2},
					{Nexthdr: icmp, TrafficDirection: ingress}:                     {label3},
				},
			},
			key: policy.Key{
				Identity:         identity1,
				Nexthdr:          icmp,
				TrafficDirection: ingress,
			},
			expect: []*Policy{
				{
					Kind:      "NetworkPolicy",
					Namespace: "ns2",
					Name:      "bar1",
				},
				{
					Kind:      "CiliumNetworkPolicy",
					Namespace: "ns3",
					Name:      "baz1",
				},
			},
		},
		{
			desc: "all policies match",
			ep: &testutils.FakeEndpointInfo{
				PolicyMap: map[policy.Key]labels.LabelArrayList{
					{DestPort: port80, Nexthdr: tcp, TrafficDirection: ingress}: {label1},
					{Nexthdr: tcp, TrafficDirection: ingress}:                   {label2},
					{TrafficDirection: ingress}:                                 {label3},
				},
			},
			key: policy.Key{
				Identity:         identity2,
				DestPort:         port80,
				Nexthdr:          tcp,
				TrafficDirection: ingress,
			},
			expect: []*Policy{
				{
					Kind:      "NetworkPolicy",
					Namespace: "ns1",
					Name:      "foo1",
				},
				{
					Kind:      "NetworkPolicy",
					Namespace: "ns2",
					Name:      "bar1",
				},
				{
					Kind:      "CiliumNetworkPolicy",
					Namespace: "ns3",
					Name:      "baz1",
				},
			},
		},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			got := lookupPoliciesForKey(tc.ep, tc.key)
			if diff := cmp.Diff(tc.expect, got); diff != "" {
				t.Errorf("Got mismatch for policies (-want +got):\n%s", diff)
			}
		})
	}
}

func TestPolicyCorrelation_correlatePolicy(t *testing.T) {
	correlator := &policyCorrelation{
		endpointGetter: &testutils.FakeEndpointGetter{
			OnGetEndpointInfo: func(ip net.IP) (endpoint v1.EndpointInfo, ok bool) {
				endpoint, ok = endpointMap[ip.String()]
				return endpoint, ok
			},
		},
	}

	testCases := []struct {
		desc   string
		f      *flow.Flow
		expect []*Policy
	}{
		{
			desc: "test",
			f:    testFlow,
			expect: []*Policy{
				{
					Kind:      "NetworkPolicy",
					Name:      "allow-all",
					Namespace: "default",
				},
			},
		},
	}
	for _, tc := range testCases {
		tc := tc
		t.Run(tc.desc, func(t *testing.T) {
			got, err := correlator.correlatePolicy(tc.f)
			if err != nil {
				t.Fatalf("Unexpected error for correlatePolicy(): %v", err)
			}
			if diff := cmp.Diff(tc.expect, got); diff != "" {
				t.Errorf("Got mismatch for policies for correlatePolicy() (-want +got):\n%s", diff)
			}
		})
	}

}

func TestK8sResouceForPolicyLabelSet(t *testing.T) {
	for _, tc := range []struct {
		desc       string
		labelArray labels.LabelArray
		wantPolicy Policy
		wantOk     bool
	}{
		{
			desc:       "empty label array",
			labelArray: labels.LabelArray{},
		},
		{
			desc: "non k8s source",
			labelArray: labels.ParseLabelArray(
				fmt.Sprintf("cilium:%s=NetworkPolicy", k8sConst.PolicyLabelDerivedFrom),
				fmt.Sprintf("k8s:%s=ns", k8sConst.PolicyLabelNamespace),
				fmt.Sprintf("k8s:%s=foo", k8sConst.PolicyLabelName)),
		},
		{
			desc: "missing ks8 resource kind label",
			labelArray: labels.ParseLabelArray(
				fmt.Sprintf("k8s:%s=ns", k8sConst.PolicyLabelNamespace),
				fmt.Sprintf("k8s:%s=foo", k8sConst.PolicyLabelName)),
		},
		{
			desc: "missing ks8 resource namespace label",
			labelArray: labels.ParseLabelArray(
				fmt.Sprintf("k8s:%s=NetworkPolicy", k8sConst.PolicyLabelDerivedFrom),
				fmt.Sprintf("k8s:%s=foo", k8sConst.PolicyLabelName)),
		},
		{
			desc: "missing ks8 resource name label",
			labelArray: labels.ParseLabelArray(
				fmt.Sprintf("k8s:%s=NetworkPolicy", k8sConst.PolicyLabelDerivedFrom),
				fmt.Sprintf("k8s:%s=ns", k8sConst.PolicyLabelNamespace)),
		},
		{
			desc: "valid label set",
			labelArray: labels.ParseLabelArray(
				fmt.Sprintf("k8s:%s=NetworkPolicy", k8sConst.PolicyLabelDerivedFrom),
				fmt.Sprintf("k8s:%s=foo", k8sConst.PolicyLabelName),
				fmt.Sprintf("k8s:%s=ns", k8sConst.PolicyLabelNamespace)),
			wantPolicy: Policy{Kind: "NetworkPolicy", Namespace: "ns", Name: "foo"},
			wantOk:     true,
		},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			got, gotOk := k8sResourceForPolicyLabelSet(tc.labelArray)
			if gotOk != tc.wantOk {
				t.Fatalf("k8sResouceForPolicyLabelSet()= _, %t, want %t", gotOk, tc.wantOk)
			}
			if diff := cmp.Diff(tc.wantPolicy, got); diff != "" {
				t.Errorf("Got diff for Policy (-want +got):\n%s", diff)
			}
		})
	}
}
