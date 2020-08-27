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
	"time"

	"github.com/cilium/cilium/api/v1/flow"
	"github.com/golang/protobuf/ptypes"
)

func isAllow(f *flow.Flow) bool {
	return f.GetVerdict() == flow.Verdict_FORWARDED
}

func isNodeTraffic(entry *PolicyActionLogEntry) bool {
	// GKE node network policy is enabled for ingress connections only.
	return entry.Connection.Direction == ConnectionDirectionIngress && entry.Dest.PodName == ""
}

func (n *networkPolicyLogger) flowToPolicyActionLogEntry(f *flow.Flow) (*PolicyActionLogEntry, error) {
	var entry PolicyActionLogEntry
	var conn = &entry.Connection
	switch f.GetTrafficDirection() {
	case flow.TrafficDirection_EGRESS:
		conn.Direction = ConnectionDirectionEgress
	case flow.TrafficDirection_INGRESS:
		conn.Direction = ConnectionDirectionIngress
	default:
		return nil, fmt.Errorf("unknown direction %d", f.GetTrafficDirection())
	}
	if f.GetVerdict() == flow.Verdict_FORWARDED {
		entry.Disposition = PolicyDispositionAllow
	} else {
		entry.Disposition = PolicyDispositionDeny
	}

	conn.SrcIP = f.GetIP().GetSource()
	conn.DestIP = f.GetIP().GetDestination()

	if tcp := f.GetL4().GetTCP(); tcp != nil {
		conn.Protocol = "tcp"
		conn.DestPort = uint16(tcp.GetDestinationPort())
		conn.SrcPort = uint16(tcp.GetSourcePort())
	} else if udp := f.GetL4().GetUDP(); udp != nil {
		conn.Protocol = "udp"
		conn.DestPort = uint16(udp.GetDestinationPort())
		conn.SrcPort = uint16(udp.GetSourcePort())
	} else if icmp := f.GetL4().GetICMPv4(); icmp != nil {
		conn.Protocol = "icmp"
	} else {
		// TODO(zangli): handle IPv6
		conn.Protocol = "unknown"
	}

	wl := f.GetSource()
	if wl != nil && wl.GetPodName() != "" {
		entry.Src = Workload{
			PodName:      wl.GetPodName(),
			PodNamespace: wl.GetNamespace(),
		}
	} else {
		entry.Src = Workload{
			Instance: conn.SrcIP,
		}
	}
	wl = f.GetDestination()
	if wl != nil && wl.GetPodName() != "" {
		entry.Dest = Workload{
			PodName:      wl.GetPodName(),
			PodNamespace: wl.GetNamespace(),
		}
	} else {
		entry.Dest = Workload{
			Instance: conn.DestIP,
		}
	}
	entry.Count = 1
	if n.cfg.logNodeName {
		entry.NodeName = f.GetNodeName()
	}
	if t, err := ptypes.Timestamp(f.GetTime()); err == nil {
		entry.Timestamp = t
	} else {
		entry.Timestamp = time.Now()
	}

	if isNodeTraffic(&entry) {
		// Node policy correlation is not supported yet.
		return &entry, nil
	}
	if policies, err := n.policyCorrelator.correlatePolicy(f); err != nil {
		return nil, err
	} else {
		entry.Policies = policies
	}
	return &entry, nil
}
