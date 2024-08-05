package controller

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"sync/atomic"

	"github.com/cilium/cilium/pkg/ebpf"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/k8s/types"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maps/egressmap"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/time"
	"github.com/cilium/cilium/pkg/trigger"
	"github.com/cilium/hive/cell"
	"golang.org/x/sync/errgroup"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sLabels "k8s.io/apimachinery/pkg/labels"
	apitypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/workqueue"
)

// Only modify this in testing
var nodeGetIPv4Fn = node.GetIPv4

// endpointID is based on endpoint's UID
type endpointID = apitypes.UID

type Params struct {
	cell.In

	Config         Config
	Lifecycle      cell.Lifecycle
	DaemonConfig   *option.DaemonConfig
	Clientset      k8sClient.Clientset
	PolicyMap      egressmap.PolicyMap
	CiliumEndpoint resource.Resource[*types.CiliumEndpoint]
}

// Controller for egress routing policy.
type Controller struct {
	// A set of CEPs which are allowed egress access.
	// This should be guarded by `mu`.
	matchedEndpointsByIP          map[netip.Addr]endpointID
	matchedEndpointsByEndpointUID map[endpointID]map[netip.Addr]struct{}
	policyMap                     egressmap.PolicyMap
	config                        Config
	egressAccessLabelSelectors    []k8sLabels.Selector
	// Subscribe to CEP events here
	cepResource resource.Resource[*types.CiliumEndpoint]
	// reconciliationTrigger is the trigger used to reconcile the state of
	// the node with the desired strict egress policy state.
	reconciliationTrigger *trigger.Trigger
	// A counter storing the number of events we have handled.
	reconciliationEventsCount atomic.Uint64

	mu lock.RWMutex
}

// NewController returns a new controller for egress routing policy.
func NewController(params *Params) (*Controller, error) {
	c := &Controller{
		cepResource:                   params.CiliumEndpoint,
		policyMap:                     params.PolicyMap,
		matchedEndpointsByIP:          make(map[netip.Addr]endpointID),
		matchedEndpointsByEndpointUID: make(map[endpointID]map[netip.Addr]struct{}),
		config:                        params.Config,
	}

	labelSelectors, err := generateLabelSelectors(c.config.StrictEgressPolicyValidationAllowAccessLabels)
	if err != nil {
		return nil, fmt.Errorf("generate label selectors: %w", err)
	}
	for _, labelSelector := range labelSelectors {
		if selector, err := metav1.LabelSelectorAsSelector(labelSelector); err == nil {
			c.egressAccessLabelSelectors = append(c.egressAccessLabelSelectors, selector)
		} else {
			return nil, fmt.Errorf("create label selector: %w", err)
		}
	}

	t, err := trigger.NewTrigger(trigger.Parameters{
		Name:        "strict_egress_policy_validation_reconciliation",
		MinInterval: c.config.StrictEgressPolicyValidationReconciliationTriggerInterval,
		TriggerFunc: func(reasons []string) {
			reason := strings.Join(reasons, ", ")
			log.WithField(logfields.Reason, reason).Debug("reconciliation triggered")

			c.reconcile()
		},
	})
	if err != nil {
		return nil, err
	}
	c.reconciliationTrigger = t

	ctx, cancel := context.WithCancel(context.Background())
	errGrp, egCtx := errgroup.WithContext(ctx)
	params.Lifecycle.Append(cell.Hook{
		OnStart: func(hc cell.HookContext) error {
			errGrp.Go(func() error {
				return c.ProcessEvents(egCtx)
			})

			return nil
		},
		OnStop: func(hc cell.HookContext) error {
			cancel()

			return errGrp.Wait()
		},
	})

	log.WithField("labelSelectors", c.egressAccessLabelSelectors).
		Info("Initialized Strict Egress Policy Validation Controller")

	return c, nil
}

func (c *Controller) isLocalCEP(cep *types.CiliumEndpoint) bool {
	if cep == nil || cep.Networking == nil {
		return false
	}
	return cep.Networking.NodeIP == nodeGetIPv4Fn().String()
}

/* upsertEndpoint adds/updates the IP of the given CiliumEndpoint to egress map:
 *   - source IP is set to the CiliumEndpoint IP
 *   - destination IP is set to 0.0.0.0/0 to match any egress traffic.
 *   - gatewayIP is set to node's IP, so that egress traffic from CiliumEndpoint will go though local endpoint's SNAT logic.
 *   - egressIP is set to 255.255.255.254 for special handling in bpf_lxc.
 */
func (c *Controller) upsertEndpoint(ep *types.CiliumEndpoint) error {
	if c == nil || ep == nil {
		return nil
	}
	log := log.WithField("ciliumEndpoint", ep.GetNamespace()+"/"+ep.GetName())
	defer c.reconciliationEventsCount.Add(1)

	ipSet := ipsOfCiliumEndpoint(ep)
	var ipSlice []netip.Addr
	for ip := range ipSet {
		ipSlice = append(ipSlice, ip)
	}
	log = log.WithField("IPs", ipSlice)
	labelArray := labels.ParseLabelArrayFromArray(ep.Identity.Labels)
	labelsSet := convertLabelArrayToK8SLabelSet(labelArray)

	c.mu.Lock()
	defer c.mu.Unlock()

	log.WithField("foundLabels", labelsSet).Debug("Checking label matching")
	ipToDeleted := make(map[netip.Addr]struct{})
	for ip := range c.matchedEndpointsByEndpointUID[ep.UID] {
		if _, ok := ipSet[ip]; !ok {
			ipToDeleted[ip] = struct{}{}
		}
	}
	// The cep doesn't have, or no longer has the infra-access label.
	if !matchesAnyLabelSelectors(c.egressAccessLabelSelectors, labelsSet) {
		// For update case, check if there is any change in the label matching.
		log.Debug("Removing strict egress policy since there is no matching label")
		delete(c.matchedEndpointsByEndpointUID, ep.UID)
		// Delete both the old IPs and the new IPs.
		for ip := range ipSet {
			ipToDeleted[ip] = struct{}{}
		}
		return c.delEndpointIPs(ipToDeleted, true, true)
	}

	// The label matches.
	// Find old IPs assigned to this ep ID (ideally none).
	// delete the diff.
	for ip := range ipSet {
		delete(ipToDeleted, ip)
	}
	c.matchedEndpointsByEndpointUID[ep.UID] = ipSet
	c.delEndpointIPs(ipToDeleted, true, true)

	if err := c.addEndpointIPs(ep, ipSet); err != nil {
		return fmt.Errorf("add endpoint IPs: %w", err)
	}
	log.Debug("Added all CEP IPs to egress map")
	return nil
}

func (c *Controller) deleteEndpoint(ep *types.CiliumEndpoint) error {
	if c == nil || ep == nil {
		return nil
	}
	log := log.WithField("ciliumEndpoint", ep.GetNamespace()+"/"+ep.GetName()).
		WithField("action", "delete")
	defer c.reconciliationEventsCount.Add(1)

	ipSet := ipsOfCiliumEndpoint(ep)
	var ipSlice []netip.Addr
	for ip := range ipSet {
		ipSlice = append(ipSlice, ip)
	}
	log = log.WithField("IPs", ipSlice)

	// Find all previous IPs on record, we need to delete them as well.
	c.mu.Lock()
	defer c.mu.Unlock()
	for ip := range c.matchedEndpointsByEndpointUID[ep.UID] {
		ipSet[ip] = struct{}{}
	}
	delete(c.matchedEndpointsByEndpointUID, ep.UID)

	if err := c.delEndpointIPs(ipSet, false, false); err != nil {
		return fmt.Errorf("delete endpoint IPs: %w", err)
	}
	log.Debug("Removed all CEP IPs from egress map")
	return nil
}

// ** Lock must be held before calling this function.
func (c *Controller) addEndpointIPs(ep *types.CiliumEndpoint, ipSet map[netip.Addr]struct{}) error {
	if c == nil || len(ipSet) == 0 {
		return nil
	}

	for ip := range ipSet {
		// When ep is not nil, we want to make sure the internal status is updated as well.
		// Otherwise, we will consider this internal status is already updated. (e.g. this function is triggered from reconcile())
		if ep != nil {
			// CEP IP should not change, and there should not be IP conflict within the same VPC.
			// so when the IP has been programmed before, return directly.
			if _, ok := c.matchedEndpointsByIP[ip]; ok {
				continue
			}
			// Add IP to map first, so that even if the logic fails below in the loop, the entry may
			// still be recreated later during reconciliaton.
			c.matchedEndpointsByIP[ip] = ep.UID
		}

		log := log.WithField("IP", ip)
		if val, err := c.policyMap.Lookup(ip, strictEgressPolicyValidationDstCIDR); err == nil && strictEgressPolicyValidationEgressIP != val.EgressIP.Addr() {
			log.WithField("existingEgressIP", val.EgressIP).Debug("CEP has existing egress gateway policy entry. Skip programming for infra-access policy")
			continue
		}
		// Set gateway IP to current node's IP. This will force the cep egress using node's IP.
		if err := c.policyMap.Update(ip, strictEgressPolicyValidationDstCIDR, strictEgressPolicyValidationEgressIP, strictEgressPolicyValidationGatewayIP); err != nil {
			log.WithError(err).Error("Failed to add CEP IPto egressmap")
			continue
		}
		log.Debug("egressMap updated")
	}
	return nil
}

// delIPs removes the given IPs from egress gateway policy map.
// When `verify` is true, we look up the egress map to make sure the existing entry is managed by us (having our special egress IP) before deletion.
// This prevent us removing a legit egress gateway policy by accident.
// When `verify` is false, we just remove the egress policy entry blindly. When the CEP is gone, we don't need to verify anything.
// When `checkCache` is true, we will assume the local cache is synchronized with egress map.
// ** Lock must be held before calling this function.
func (c *Controller) delEndpointIPs(ipSet map[netip.Addr]struct{}, verify bool, checkCache bool) error {
	if c == nil || len(ipSet) == 0 {
		return nil
	}

	for ip := range ipSet {
		log := log.WithField("IP", ip)
		if checkCache {
			// Skip as this IP does not exist in cache.
			if _, ok := c.matchedEndpointsByIP[ip]; !ok {
				continue
			}
		}
		delete(c.matchedEndpointsByIP, ip)

		if verify {
			if val, err := c.policyMap.Lookup(ip, strictEgressPolicyValidationDstCIDR); err == nil && strictEgressPolicyValidationEgressIP != val.EgressIP.Addr() {
				log.WithField("existingEgressIP", val.EgressIP).Debug("cep has other existing egress gateway policy entry. Skip cleaning it up")
			}
		}
		if err := c.policyMap.Delete(ip, strictEgressPolicyValidationDstCIDR); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			log.WithError(err).Error("Failed to delete CEP IP from egress map")
		} else {
			log.Debug("Successfully deleted CEP IP from egress map")
		}
	}
	return nil
}

/* IsStrictEgressPolicy returns true when the given egress policy is a valid strict egress policy.
 * This indicates:
 *   - The egress gateway IP is the special egress IP used by strict egress policy.
 *
 * This helps the clean up process of egressgateway manager to determine if a policy is stale and should be deleted.
 */
func (c *Controller) IsStrictEgressPolicy(key *egressmap.EgressPolicyKey4, val *egressmap.EgressPolicyVal4) bool {
	if c == nil || key == nil || val == nil {
		return false
	}
	// Egress IP is not the same.
	return strictEgressPolicyValidationEgressIP.Compare(val.EgressIP.Addr()) == 0
}

/* IsValidStrictEgressPolicy returns true when the given egress policy is a valid strict egress policy.
 * This indicates:
 *   - The egress gateway policy is in strict egress gateway format
 *   - The source IP mentioned in the given egress gateway policy is valid
 *
 * This helps the clean up process of egressgateway manager to determine if a policy is stale and should be deleted.
 */
func (c *Controller) IsValidStrictEgressPolicy(key *egressmap.EgressPolicyKey4, val *egressmap.EgressPolicyVal4) bool {
	if c == nil || key == nil || val == nil {
		return false
	}
	// Destination CIDR is not the same
	if key.GetDestCIDR() != strictEgressPolicyValidationDstCIDR {
		return false
	}
	// Egress IP is not correct.
	if !val.Match(strictEgressPolicyValidationEgressIP, strictEgressPolicyValidationGatewayIP) {
		return false
	}

	c.mu.RLock()
	defer c.mu.RUnlock()
	// If the CEP is not recorded locally, the given egress policy may be a stale entry.
	if _, ok := c.matchedEndpointsByIP[key.GetSourceIP()]; !ok {
		return false
	}
	return true
}

func (c *Controller) ProcessEvents(ctx context.Context) error {
	if c == nil {
		return nil
	}
	log.Info("Starting processing events")

	// here we try to mimic the same exponential backoff retry logic used by
	// the identity allocator, where the minimum retry timeout is set to 20
	// milliseconds and the max number of attempts is 16 (so 20ms * 2^16 ==
	// ~20 minutes)
	endpointsRateLimit := workqueue.NewItemExponentialFailureRateLimiter(time.Millisecond*20, time.Minute*20)
	endpointEvents := c.cepResource.Events(ctx, resource.WithRateLimiter(endpointsRateLimit))

	for {
		select {
		case <-ctx.Done():
			return nil

		case event := <-endpointEvents:
			log := log.WithField("action", event.Kind)
			if event.Object != nil {
				log = log.WithField("ciliumEndpoint", event.Object.GetNamespace()+"/"+event.Object.GetName())

				if !c.isLocalCEP(event.Object) {
					event.Done(nil)
					c.reconciliationEventsCount.Add(1)
					continue
				}
			}
			log.Debug("Processing event")

			switch event.Kind {
			case resource.Sync:
				c.reconciliationTrigger.TriggerWithReason("k8s endpoint sync triggered")
				event.Done(nil)
			case resource.Upsert:
				event.Done(c.upsertEndpoint(event.Object))
			case resource.Delete:
				event.Done(c.deleteEndpoint(event.Object))
			}
		}
	}
}

/*
 * reconcile reconciles the existing egress gateway rule to be synchronized with
 * the current internal states (e.g. matchedEndpoints).
 * It will
 */
func (c *Controller) reconcile() error {
	if c == nil {
		return nil
	}
	defer c.reconciliationEventsCount.Add(1)

	// Take a snapshot of the egress policy map.
	staleEgressPolicies := map[egressmap.EgressPolicyKey4]egressmap.EgressPolicyVal4{}
	foundEgressPolicies := map[egressmap.EgressPolicyKey4]egressmap.EgressPolicyVal4{}
	policyPopulator := func(key *egressmap.EgressPolicyKey4, val *egressmap.EgressPolicyVal4) {
		// Only care about strict egress policy
		if !c.IsStrictEgressPolicy(key, val) {
			return
		}
		if !c.IsValidStrictEgressPolicy(key, val) {
			staleEgressPolicies[*key] = *val
			return
		}
		foundEgressPolicies[*key] = *val
	}
	if err := c.policyMap.IterateWithCallback(policyPopulator); err != nil {
		log.WithError(err).Error("Failed to iterate over egress map")
		return err
	}

	c.mu.RLock()
	defer c.mu.RUnlock()
	// Delete stale policies
	for key := range staleEgressPolicies {
		ip := key.GetSourceIP()
		log := log.WithField("IP", ip)

		if err := c.policyMap.Delete(ip, strictEgressPolicyValidationDstCIDR); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			log.WithError(err).Error("Failed to delete stale CEP IP from egress map")
			continue
		}
		log.Debug("Deleted stale CEP IP from egress map")
		// Do not delete IP from matchedEndpointsByIP here.
		// This policy entry may be malformed, but the endpoint itself is a valid matched endpoint.
		// So we expect the following section to add the correct policy entry back.
	}

	// Add missing policies
	missingIPSet := make(map[netip.Addr]struct{})
	for ip := range c.matchedEndpointsByIP {
		key := egressmap.EgressPolicyKey4{
			SourceIP: ip.As4(),
			DestCIDR: strictEgressPolicyValidationDstCIDR.Addr().As4(),
		}
		if _, ok := foundEgressPolicies[key]; ok {
			continue
		}
		missingIPSet[ip] = struct{}{}
	}
	if len(missingIPSet) > 0 {
		var missingIPs []netip.Addr
		for ip := range missingIPSet {
			missingIPs = append(missingIPs, ip)
		}
		log := log.WithField("missingIPs", missingIPs)
		if err := c.addEndpointIPs(nil, missingIPSet); err != nil {
			log.WithError(err).Error("Failed to add missing CEP IPs to egress map")
			return fmt.Errorf("add missing endpoint IPs: %w", err)
		}
		log.Debug("Added missing CEP IPs to egress map")
	}

	return nil
}

func (c *Controller) Reconcile() {
	if c == nil {
		return
	}
	c.reconciliationTrigger.TriggerWithReason("external reconcile triggered")
}
