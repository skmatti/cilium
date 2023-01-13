// Copyright 2023 Google LLC
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

//go:build !privileged_tests

package controller

import (
	"errors"
	"net"
	"testing"

	"github.com/cilium/cilium/api/v1/models"
	. "github.com/cilium/cilium/pkg/gke/apis/remotenode/v1alpha1"
)

func TestUpsertWireguardTunnel(t *testing.T) {
	tests := []struct {
		name            string
		remoteNode      *RemoteNode
		wgagent         *fakeWgAgent
		ipcache         *fakeIpCache
		wantErr         bool
		wantPeerCount   int
		wantIpCacheSize int
	}{
		{
			name:       "fail to parse RemoteNode with no tunnel ip",
			remoteNode: &RemoteNode{},
			wantErr:    true,
		},
		{
			name:       "fail to parse RemoteNode with invalid tunnel ip",
			remoteNode: &RemoteNode{Spec: RemoteNodeSpec{TunnelIP: "abcd"}},
			wantErr:    true,
		},
		{
			name:       "fail to parse RemoteNode with no pod cidr",
			remoteNode: &RemoteNode{Spec: RemoteNodeSpec{TunnelIP: "1.2.3.4"}},
			wantErr:    true,
		},
		{
			name:       "fail to parse RemoteNode with invalid pod cidr",
			remoteNode: &RemoteNode{Spec: RemoteNodeSpec{TunnelIP: "1.2.3.4", PodCIDRs: []string{"abcd"}}},
			wantErr:    true,
		},
		{
			name:       "fail to upsert in ipcache",
			remoteNode: &RemoteNode{Spec: RemoteNodeSpec{TunnelIP: "1.2.3.4", PodCIDRs: []string{"1.1.1.0/24"}}},
			ipcache:    &fakeIpCache{failOnUpsert: true},
			wantErr:    true,
		},
		{
			name:       "fail to upsert wireguard peer",
			remoteNode: &RemoteNode{Spec: RemoteNodeSpec{TunnelIP: "1.2.3.4", PodCIDRs: []string{"1.1.1.0/24"}}},
			wgagent:    &fakeWgAgent{failOnUpsert: true},
			wantErr:    true,
		},
		{
			name:            "success with ipv4",
			remoteNode:      &RemoteNode{Spec: RemoteNodeSpec{TunnelIP: "1.2.3.4", PodCIDRs: []string{"1.1.1.0/24"}}},
			wantPeerCount:   1,
			wantIpCacheSize: 1,
		},
		{
			name:            "success with ipv6",
			remoteNode:      &RemoteNode{Spec: RemoteNodeSpec{TunnelIP: "1:2:3:4:aa:bb:cc:dd", PodCIDRs: []string{"10:20:30::/48"}}},
			wantPeerCount:   1,
			wantIpCacheSize: 1,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			wgagent := &fakeWgAgent{peerCount: 0}
			if test.wgagent != nil {
				wgagent = test.wgagent
			}
			ipcache := &fakeIpCache{size: 0}
			if test.ipcache != nil {
				ipcache = test.ipcache
			}
			u := Controller{wgagent: wgagent, ipcache: ipcache}
			err := u.upsertWireguardTunnel(test.remoteNode)
			if (err != nil) != test.wantErr {
				t.Errorf("%s - got error %v, want error %v", test.name, err, test.wantErr)
			}
			if wgagent.peerCount != test.wantPeerCount {
				t.Errorf("%s - peerCount updated", test.name)
			}
			if ipcache.size != test.wantIpCacheSize {
				t.Errorf("%s - ipcache updated", test.name)
			}
		})
	}
}

func TestDeleteWireguardTunnel(t *testing.T) {
	tests := []struct {
		name            string
		remoteNode      *RemoteNode
		wgagent         *fakeWgAgent
		ipcache         *fakeIpCache
		wantErr         bool
		wantPeerCount   int
		wantIpCacheSize int
	}{
		{
			name:            "fail to delete wireguard peer",
			remoteNode:      &RemoteNode{Spec: RemoteNodeSpec{TunnelIP: "1.2.3.4", PodCIDRs: []string{"1.1.1.0/24"}}},
			wgagent:         &fakeWgAgent{peerCount: 1, failOnDelete: true},
			ipcache:         &fakeIpCache{size: 1},
			wantErr:         true,
			wantPeerCount:   1,
			wantIpCacheSize: 1,
		},
		{
			name:            "fail to parse RemoteNode with no tunnel ip",
			remoteNode:      &RemoteNode{},
			wgagent:         &fakeWgAgent{peerCount: 1},
			ipcache:         &fakeIpCache{size: 1},
			wantErr:         true,
			wantPeerCount:   0, // ipcache is not cleaned up but wireguard peer config is deleted.
			wantIpCacheSize: 1,
		},
		{
			name:            "fail to parse RemoteNode with invalid tunnel ip",
			remoteNode:      &RemoteNode{Spec: RemoteNodeSpec{TunnelIP: "abcd"}},
			wgagent:         &fakeWgAgent{peerCount: 1},
			ipcache:         &fakeIpCache{size: 1},
			wantErr:         true,
			wantPeerCount:   0, // ipcache is not cleaned up but wireguard peer config is deleted.
			wantIpCacheSize: 1,
		},
		{
			name:            "fail to delete in ipcache",
			remoteNode:      &RemoteNode{Spec: RemoteNodeSpec{TunnelIP: "1.2.3.4", PodCIDRs: []string{"1.1.1.0/24"}}},
			wgagent:         &fakeWgAgent{peerCount: 1},
			ipcache:         &fakeIpCache{size: 1, failOnDelete: true},
			wantErr:         true,
			wantPeerCount:   0, // ipcache is not cleaned up but wireguard peer config is deleted.
			wantIpCacheSize: 1,
		},
		{
			name:            "success with ipv4",
			remoteNode:      &RemoteNode{Spec: RemoteNodeSpec{TunnelIP: "1.2.3.4", PodCIDRs: []string{"1.1.1.0/24"}}},
			wgagent:         &fakeWgAgent{peerCount: 1},
			ipcache:         &fakeIpCache{size: 1},
			wantPeerCount:   0,
			wantIpCacheSize: 0,
		},
		{
			name:            "success with ipv6",
			remoteNode:      &RemoteNode{Spec: RemoteNodeSpec{TunnelIP: "1:2:3:4:aa:bb:cc:dd", PodCIDRs: []string{"10:20:30::/48"}}},
			wgagent:         &fakeWgAgent{peerCount: 1},
			ipcache:         &fakeIpCache{size: 1},
			wantPeerCount:   0,
			wantIpCacheSize: 0,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			wgagent := &fakeWgAgent{peerCount: 0}
			if test.wgagent != nil {
				wgagent = test.wgagent
			}
			ipcache := &fakeIpCache{size: 0}
			if test.ipcache != nil {
				ipcache = test.ipcache
			}
			u := Controller{wgagent: wgagent, ipcache: ipcache}
			err := u.deleteWireguardTunnel(test.remoteNode)
			if (err != nil) != test.wantErr {
				t.Errorf("%s - got error %v, want error %v", test.name, err, test.wantErr)
			}
			if wgagent.peerCount != test.wantPeerCount {
				t.Errorf("%s - peerCount updated", test.name)
			}
			if ipcache.size != test.wantIpCacheSize {
				t.Errorf("%s - ipcache updated", test.name)
			}
		})
	}
}

type fakeWgAgent struct {
	peerCount    int
	failOnUpsert bool
	failOnDelete bool
}

func (f *fakeWgAgent) UpdatePeer(_, _ string, _, _ net.IP) error {
	if f.failOnUpsert {
		return errors.New("failed to upsert wireguard peer")
	}
	f.peerCount++
	return nil
}

func (f *fakeWgAgent) DeletePeer(_ string) error {
	if f.failOnDelete {
		return errors.New("failed to delete wireguard peer")
	}
	f.peerCount--
	return nil
}

func (f *fakeWgAgent) Status(_ bool) (*models.WireguardStatus, error) { return nil, nil }

type fakeIpCache struct {
	size         int
	failOnUpsert bool
	failOnDelete bool
}

func (f *fakeIpCache) DeleteRemoteNode(_, _ net.IP) error {
	if f.failOnDelete {
		return errors.New("failed to delete remote node")
	}
	f.size--
	return nil
}

func (f *fakeIpCache) UpsertRemotePods(net.IP, []*net.IPNet) error {
	if f.failOnUpsert {
		return errors.New("failed to upsert in ipcache")
	}
	f.size++
	return nil
}
