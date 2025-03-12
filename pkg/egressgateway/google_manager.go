package egressgateway

import (
	"net/netip"

	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maps/egressmap"
	"github.com/sirupsen/logrus"
)

func (manager *Manager) addMissingEgressTimeouts() {
	egressTimeouts := map[egressmap.EgressPolicyKey4]egressmap.EgressTimeoutsVal4{}
	manager.egressTimeoutsMap.IterateWithCallback(
		func(key *egressmap.EgressPolicyKey4, val *egressmap.EgressTimeoutsVal4) {
			egressTimeouts[*key] = *val
		})

	addEgressTimeouts := func(endpointIP netip.Addr, dstCIDR netip.Prefix, connectionTimeouts *egressmap.ConnectionTimeouts) {
		if connectionTimeouts == nil {
			return
		}

		timeoutsKey := egressmap.NewEgressPolicyKey4(endpointIP, dstCIDR)
		timeoutsVal, timeoutsPresent := egressTimeouts[timeoutsKey]

		if timeoutsPresent && timeoutsVal.Match(*connectionTimeouts) {
			return
		}

		logger := log.WithFields(logrus.Fields{
			logfields.SourceIP:           endpointIP,
			logfields.DestinationCIDR:    dstCIDR.String(),
			logfields.ConnectionTimeouts: connectionTimeouts.String(),
		})

		if err := manager.egressTimeoutsMap.Update(endpointIP, dstCIDR, *connectionTimeouts); err != nil {
			logger.WithError(err).Error("Error applying egress gateway timeouts")
		} else {
			logger.Debug("Egress gateway timeouts applied")
		}
	}

	for _, policyConfig := range manager.policyConfigs {
		policyConfig.forEachEndpointAndCIDRTimeouts(addEgressTimeouts)
	}
}

func (manager *Manager) matchesTimeouts(sourceIP netip.Addr,
	f func(netip.Addr, netip.Prefix, *egressmap.ConnectionTimeouts) bool) bool {
	for _, policy := range manager.policyConfigsBySourceIP[sourceIP.String()] {
		for _, ep := range policy.matchedEndpoints {
			for _, endpointIP := range ep.ips {
				if endpointIP != sourceIP {
					continue
				}

				for _, dstCIDR := range policy.dstCIDRs {
					if f(endpointIP, dstCIDR, policy.connectionTimeouts) {
						return true
					}
				}
			}
		}
	}

	return false
}

// removeUnusedEgressTimeouts is responsible for removing any entry in the egress timeouts BPF map which
// is not baked by an actual k8s CiliumEgressGatewayPolicy.
func (manager *Manager) removeUnusedEgressTimeouts() {
	egressTimeouts := map[egressmap.EgressPolicyKey4]egressmap.EgressTimeoutsVal4{}
	manager.egressTimeoutsMap.IterateWithCallback(
		func(key *egressmap.EgressPolicyKey4, val *egressmap.EgressTimeoutsVal4) {
			egressTimeouts[*key] = *val
		})

nextTimeoutKey:
	for timeoutKey, timeoutVal := range egressTimeouts {
		matchTimeout := func(endpointIP netip.Addr, dstCIDR netip.Prefix, connectionTimeout *egressmap.ConnectionTimeouts) bool {
			if timeoutKey.Match(endpointIP, dstCIDR) && connectionTimeout == nil {
				return false
			}

			return timeoutKey.Match(endpointIP, dstCIDR) && timeoutVal.Match(*connectionTimeout)
		}

		if manager.matchesTimeouts(timeoutKey.GetSourceIP(), matchTimeout) {
			continue nextTimeoutKey
		}

		logger := log.WithFields(logrus.Fields{
			logfields.SourceIP:           timeoutKey.GetSourceIP(),
			logfields.DestinationCIDR:    timeoutKey.GetDestCIDR().String(),
			logfields.ConnectionTimeouts: timeoutVal.ConnectionTimeouts.String(),
		})

		if err := manager.egressTimeoutsMap.Delete(timeoutKey.GetSourceIP(), timeoutKey.GetDestCIDR()); err != nil {
			logger.WithError(err).Error("Error removing egress gateway timeouts")
		} else {
			logger.Debug("Egress gateway timeouts removed")
		}
	}
}
