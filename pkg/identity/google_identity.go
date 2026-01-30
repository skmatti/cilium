package identity

import (
	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/option"
)

// DefaultMultiNICNodeNetwork is the default multi nic host endpoint.
const DefaultMultiNICNodeNetwork = "node-network"

var log = logrus.New()

// InitDefaultHostIdentity intitiates the reserved identity for the default
// node network.
func InitDefaultHostIdentity() {
	lbls := labels.NewReservedMultiNICHostLabels(DefaultMultiNICNodeNetwork)
	lbl := lbls[labels.IDNameMultiNICHost]
	reservedIdentities[lbl.String()] = ReservedIdentityHost
	lbls.MergeLabels(labels.LabelHost)
	AddReservedIdentityWithLabels(ReservedIdentityHost, lbls)
}

// InitMultiNICHostNumericIdentitySet adds multi nic host identities from
// the given map of identities and multi nic node network name.
func InitMultiNICHostNumericIdentitySet(idMap map[string]string) error {
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
		// Add multi nic host identity.
		lbls := labels.NewReservedMultiNICHostLabels(nodeNetwork)
		lbl := lbls[labels.IDNameMultiNICHost]
		reservedIdentities[lbl.String()] = ni
		reservedIdentityNames[ni] = lbl.String()
		// Add local host and multi nic host labels to the identity.
		// Multi nic host label takes precedence.
		lbls.MergeLabels(labels.LabelHost)
		AddReservedIdentityWithLabels(ni, lbls)
		log.WithFields(logrus.Fields{
			"numeric-identity": ni.Uint32(),
			"node-network":     nodeNetwork,
			"labels":           lbls,
		}).Info("Added multi nic host identity")
	}
	return nil
}

// DeleteReservedIdentity deletes the given reserved identity.
// Currently used only for tests.
func DeleteReservedIdentity(ni NumericIdentity) error {
	if err := DelReservedNumericIdentity(ni); err != nil {
		return err
	}
	cacheMU.Lock()
	delete(reservedIdentityCache, ni)
	cacheMU.Unlock()
	return nil
}

// IsMultiNICHostID returns true if the given ID is a multi nic host.
func IsMultiNICHostID(ni NumericIdentity) bool {
	if !option.Config.EnableGoogleMultiNICHostFirewall {
		return false
	}

	id := LookupReservedIdentity(ni)
	if id == nil {
		return false
	}

	_, ok := id.Labels[labels.IDNameMultiNICHost]
	return ok
}

func ReservedMultiNICHostIDForLabels(lbls labels.Labels) (NumericIdentity, bool) {
	hostLbl, ok := lbls[labels.IDNameMultiNICHost]
	if !ok {
		return IdentityUnknown, false
	}
	id := GetReservedID(hostLbl.String())
	if id == IdentityUnknown {
		return id, false
	}
	return id, true
}
