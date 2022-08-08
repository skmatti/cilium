// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipcache

import (
	"errors"
	"net"

	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/source"
	"github.com/sirupsen/logrus"
)

func (ipc *IPCache) UpsertRemotePods(remoteNodeIP net.IP, cidr []*net.IPNet) error {
	for _, cdr := range cidr {
		_, err := ipc.Upsert(cdr.String(), remoteNodeIP, 0, nil, Identity{
			ID:     identity.ReservedIdentityUnmanaged,
			Source: source.KVStore,
		})
		if err != nil {
			return err
		}
	}
	return nil
}

func (ipc *IPCache) DeleteRemoteNode(nodeIPv4, nodeIPv6 net.IP) error {
	ipc.mutex.Lock()
	defer ipc.mutex.Unlock()
	scopedLog := log.WithFields(logrus.Fields{
		logfields.NodeIPv4: nodeIPv4,
		logfields.NodeIPv6: nodeIPv6,
	})
	podCidr := ipc.LookupByHostRLocked(nodeIPv4, nodeIPv6)
	for _, cidr := range podCidr {
		id, exists := ipc.LookupByIPRLocked(cidr.String())
		if !exists {
			scopedLog.WithField("PodCidr", cidr).Debug("Looked up range does not exist")
		}
		if id.Source != source.KVStore {
			scopedLog.WithFields(logrus.Fields{
				"PodCidr":          cidr,
				logfields.Identity: id,
			}).Error("Not allowed to delete remote node which hosts non-KVStore pod ranges")
			return errors.New("pod range not sourced from KVStore, refusing to delete RemoteNode")
		}
	}

	for _, cidr := range podCidr {
		_, exists := ipc.LookupByIPRLocked(cidr.String())
		if exists {
			ipc.deleteLocked(cidr.String(), source.KVStore)
		}
	}

	return nil
}
