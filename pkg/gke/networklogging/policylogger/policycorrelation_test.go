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
	"testing"

	"github.com/cilium/cilium/pkg/hubble/testutils"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/policy/trafficdirection"
	"github.com/cilium/cilium/pkg/u8proto"
	"github.com/google/go-cmp/cmp"
)

func TestLookUpPolicyForKey(t *testing.T) {
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

	label1 := labels.ParseLabelArray("k8s:policy.name=foo1", "k8s:policy.ns=bar1")
	label2 := labels.ParseLabelArray("k8s:policy.name=foo2", "k8s:policy.ns=bar2")
	label3 := labels.ParseLabelArray("k8s:policy.name=foo3", "k8s:policy.ns=bar3")

	for _, tc := range []struct {
		desc   string
		ep     *testutils.FakeEndpointInfo
		key    policy.Key
		expect labels.LabelArrayList
	}{
		{
			desc: "empty endpoint and key",
			ep:   &testutils.FakeEndpointInfo{},
		},
		{
			desc: "empty endpoint and non-empty key",
			ep:   &testutils.FakeEndpointInfo{},
			key: policy.Key{
				Identity: identity1,
				Nexthdr:  tcp,
			},
		},
		{
			desc: "allow all endpoint matches",
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
			expect: labels.LabelArrayList{label1},
		},
		{
			desc: "allow all endpoint does not match",
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
			desc: "allow tcp protocol endpoint matches",
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
			expect: labels.LabelArrayList{label1},
		},
		{
			desc: "allow tcp protocol endpoint does not match",
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
			desc: "allow tcp port 80 endpoint matches",
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
			expect: labels.LabelArrayList{label1},
		},
		{
			desc: "allow tcp port 80 endpoint does not match",
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
			desc: "allow single identity endpoint matches",
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
			expect: labels.LabelArrayList{label1},
		},
		{
			desc: "allow single identity endpoint does not match",
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
			desc: "multiple endpoints match multiple",
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
			expect: labels.LabelArrayList{label2, label3},
		},
		{
			desc: "multiple endpoints (icmp) match multiple",
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
			expect: labels.LabelArrayList{label2, label3},
		},
		{
			desc: "multiple endpoints match all",
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
			expect: labels.LabelArrayList{label1, label2, label3},
		},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			got, _, _ := lookupPolicyForKey(tc.ep, tc.key)
			if diff := cmp.Diff(tc.expect, got); diff != "" {
				t.Errorf("Got mismatch for policies (-want +got):\n%s", diff)
			}
		})
	}
}
