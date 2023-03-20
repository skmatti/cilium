package identity

import (
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/option"
)

// DefaultMultiNICNodeNetwork is the default multi nic host endpoint.
const DefaultMultiNICNodeNetwork = "node-network"

// InitDefaultHostIdentity intitiates the reserved identity for the default
// node network.
func InitDefaultHostIdentity() {
	reservedIdentities[labels.NewReservedMultiNICHostLabels(DefaultMultiNICNodeNetwork).String()] = ReservedIdentityHost
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
		reservedIdentityLabels[ni] = lbls
		AddReservedIdentityWithLabels(ni, lbls)
	}
	return nil
}

// DeleteReservedIdentity deletes the given reserved identity.
// Currently used only for tests.
func DeleteReservedIdentity(ni NumericIdentity) error {
	if err := DelReservedNumericIdentity(ni); err != nil {
		return err
	}
	delete(reservedIdentityLabels, ni)
	delete(reservedIdentityCache, ni)
	return nil
}

// IsMultiNICHostID returns true if the given ID is a multi nic host.
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
