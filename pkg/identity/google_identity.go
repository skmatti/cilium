// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package identity

import (
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/option"
	"github.com/sirupsen/logrus"
)

func AddMultiNICHostNumericIdentitySet(idMap map[string]string) error {
	if !option.Config.EnableGoogleMultiNICHostFirewall {
		return nil
	}
	for id := range idMap {
		ni, err := ParseNumericIdentity(id)
		if err != nil {
			return err
		}
		if !IsUserReservedIdentity(ni) {
			return ErrNotUserIdentity
		}
	}
	for id, nodeNetwork := range idMap {
		ni, _ := ParseNumericIdentity(id)
		// Add host identity
		lbls := labels.ReservedMultiNICHostLabels(nodeNetwork)
		lbl := lbls[labels.IDNameMultiNICHost]
		reservedIdentities[lbl.String()] = ni
		reservedIdentityNames[ni] = lbl.String()
		reservedIdentityLabels[ni] = lbls
		AddReservedIdentity(ni, lbl.String())
		// Add remote-node identity
		remoteLbls := labels.ReservedMultiNICRemoteHostLabels(nodeNetwork)
		remoteLbl := lbls[labels.IDNameMultiNICRemoteHost]
		remoteni := RemoteMultiNICHostID(ni)
		reservedIdentities[remoteLbl.String()] = remoteni
		reservedIdentityNames[remoteni] = remoteLbl.String()
		reservedIdentityLabels[remoteni] = remoteLbls
		AddReservedIdentity(remoteni, remoteLbl.String())
		log.WithFields(logrus.Fields{
			"id":           ni,
			"remoteid":     remoteni,
			"node-network": nodeNetwork,
			"identities":   reservedIdentities,
		}).Info("Adding multinic host identity")
	}
	return nil
}

// RemoteMultiNICHostID returns the remote host identity for given identity.
func RemoteMultiNICHostID(ni NumericIdentity) NumericIdentity {
	return NumericIdentity(ni.Uint32() + 1)
}

func IsMultiNICHostID(ni NumericIdentity) bool {
	if !option.Config.EnableGoogleMultiNICHostFirewall {
		return false
	}

	lbls, ok := reservedIdentityLabels[ni]
	if !ok {
		return false
	}

	_, ok = lbls[labels.IDNameMultiNICHost]
	return ok
}

func IsMultiNICRemoteHostID(ni NumericIdentity) bool {
	if !option.Config.EnableGoogleMultiNICHostFirewall {
		return false
	}

	lbls, ok := reservedIdentityLabels[ni]
	if !ok {
		return false
	}

	_, ok = lbls[labels.IDNameMultiNICRemoteHost]
	return ok
}

func reservedMultiNICHostIDForLabels(lbls labels.Labels) NumericIdentity {
	hostLbl := lbls.FindLabelKey(labels.IDNameMultiNICHost)
	if hostLbl != nil {
		log.WithFields(logrus.Fields{
			"id": hostLbl.String(),
		}).Info("GetReservedID host")
		return GetReservedID(hostLbl.String())
	}

	hostLbl = lbls.FindLabelKey(labels.IDNameMultiNICRemoteHost)
	if hostLbl != nil {
		log.WithFields(logrus.Fields{
			"id": hostLbl.String(),
		}).Info("GetReservedID remote")
		return GetReservedID(hostLbl.String())
	}
	return IdentityUnknown
}
