package egressgateway

import (
	"context"
	"net/netip"

	"github.com/cilium/cilium/pkg/inctimer"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maps/egressmap"
	"github.com/cilium/cilium/pkg/time"
	"github.com/sirupsen/logrus"
)

const (
	pendingIdentityResolverInterval = 1 * time.Second
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

// GoogleManager stores the endpoint/policy data specific to google features.
type googleManager struct {
	pendingDataStoreLock lock.Mutex

	// pendingIPCacheDeleteDataStore stores endpoints which are pending deletion.
	pendingIPCacheDeleteDataStore map[endpointID]bool

	// pendingEPDataStore stores endpoints whose labels have to be resolved.
	pendingEPDataStore map[endpointID]*endpointMetadata

	pendingIdentityExpiryDuration time.Duration
}

func NewGoogleManager(pendingIdentityExpiryDuration int) googleManager {
	return googleManager{
		pendingIPCacheDeleteDataStore: make(map[endpointID]bool),
		pendingEPDataStore:            make(map[endpointID]*endpointMetadata),
		pendingIdentityExpiryDuration: time.Duration(pendingIdentityExpiryDuration) * time.Second,
	}
}

// resolvePendingIdentities resolves identities of endpoints which could not be
// resolved during the initial endpoint add notifications.
func (manager *Manager) resolvePendingIdentities() {
	logger := log.WithField("retry", "resolvePendingIdentities")
	runReconcile := false
	manager.Lock()
	defer manager.Unlock()

	err := manager.PendingDataStoreUpdate(func() error {
		for epID := range manager.pendingIPCacheDeleteDataStore {
			delete(manager.pendingEPDataStore, epID)
			delete(manager.epDataStore, epID)
			delete(manager.pendingIPCacheDeleteDataStore, epID)
			runReconcile = true
		}

		for epID, epData := range manager.pendingEPDataStore {
			epLogger := logger.WithFields(logrus.Fields{
				logfields.K8sEndpointName: epID.Name,
				logfields.K8sNamespace:    epID.Namespace,
				logfields.Identity:        epData.identityID,
			})

			identityLabels, err := manager.getIdentityLabels(uint32(epData.identityID))
			if err != nil {
				epLogger.WithError(err).Error("Failed to get identity labels for endpoint")
				if time.Now().After(epData.expirationTime) {
					delete(manager.pendingEPDataStore, epID)
					epLogger.WithError(err).Info("pending endpoint expired, removing from pendingEPDataStore")
				}
				continue
			}
			epData.labels = identityLabels.K8sStringMap()
			epLogger.Debug("Endpoint Added")

			// Move from pending endpoint to epDataStore
			manager.epDataStore[epID] = epData
			delete(manager.pendingEPDataStore, epID)

			// Run reconcile loop
			runReconcile = true
		}
		return nil
	})
	if err != nil {
		return
	}

	if runReconcile {
		manager.setEventBitmap(eventUpdateEndpoint)
		manager.reconciliationTrigger.TriggerWithReason("resolving pending identities")
	}
}

// runPendingIdentityResolverThread spawns a goroutine that periodically checks
// for pending identities and resolves them.
func (manager *Manager) runPendingIdentityResolverThread(ctx context.Context) {
	go func() {
		retryTimer, _ := inctimer.New()

		log.Info("Starting go routine to resolve pending identities")
		for {
			select {
			case <-retryTimer.After(pendingIdentityResolverInterval):
				manager.resolvePendingIdentities()
			case <-ctx.Done():
				return
			}
		}
	}()
}
