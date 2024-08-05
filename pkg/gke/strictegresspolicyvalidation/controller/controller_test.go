package controller

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/cilium/cilium/pkg/bpf"
	k8sTypes "github.com/cilium/cilium/pkg/k8s/types"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/maps/egressmap"
	"github.com/cilium/cilium/pkg/node"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/testutils"
	testidentity "github.com/cilium/cilium/pkg/testutils/identity"
	"github.com/cilium/ebpf/rlimit"
	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"
)

const (
	node1   = "k8s1"
	node1IP = "192.168.1.1"

	ep1IP        = "10.0.0.1"
	ep2IP        = "10.0.0.2"
	ep2EgressIP  = "10.100.100.100"
	ep2GatewayIP = "10.100.0.1"
)

var (
	identityAllocator = testidentity.NewMockIdentityAllocator(nil)

	ep1Labels = map[string]string{
		"networking.private.gdc.goog/infra-access": "enabled",
	}
	ep1EgressRule = egressRule{
		sourceIP:  ep1IP,
		destCIDR:  strictEgressPolicyValidationDstCIDR.String(),
		egressIP:  strictEgressPolicyValidationEgressIP.String(),
		gatewayIP: strictEgressPolicyValidationGatewayIP.String(),
	}
	ep2EgressRule = egressRule{
		sourceIP:  ep2IP,
		destCIDR:  strictEgressPolicyValidationDstCIDR.String(),
		egressIP:  ep2EgressIP,
		gatewayIP: ep2GatewayIP,
	}
)

type StrictEgressPolicyTestSuite struct {
	controller  *Controller
	cepResource fakeResource[*k8sTypes.CiliumEndpoint]
}

func setupControllerTestSuite(t testing.TB) *StrictEgressPolicyTestSuite {
	testutils.PrivilegedTest(t)

	bpf.CheckOrMountFS("")
	err := rlimit.RemoveMemlock()
	require.NoError(t, err)

	nodeGetIPv4Fn = func() net.IP {
		return net.ParseIP(node1IP)
	}
	nodeTypes.SetName(node1)
	node.SetTestLocalNodeStore()
	t.Cleanup(func() {
		nodeGetIPv4Fn = node.GetIPv4
		node.UnsetTestLocalNodeStore()
	})

	k := &StrictEgressPolicyTestSuite{}
	k.cepResource = make(fakeResource[*k8sTypes.CiliumEndpoint])

	lc := hivetest.Lifecycle(t)
	policyMap := egressmap.CreatePrivatePolicyMap(lc, egressmap.DefaultPolicyConfig)

	k.controller, err = NewController(&Params{
		Lifecycle: lc,
		Config: Config{
			EnableStrictEgressPolicyValidation:                        true,
			StrictEgressPolicyValidationAllowAccessLabels:             DefaultStrictEgressPolicyValidationAllowAccessLabels,
			StrictEgressPolicyValidationReconciliationTriggerInterval: 1 * time.Millisecond,
		},
		DaemonConfig:   &option.DaemonConfig{ConfigPatchMutex: new(lock.RWMutex)},
		PolicyMap:      policyMap,
		CiliumEndpoint: k.cepResource,
	})
	require.NoError(t, err)
	require.NotNil(t, k.controller)

	return k
}

func TestSyncEndpoint(t *testing.T) {
	k := setupControllerTestSuite(t)
	eventCount := k.controller.reconciliationEventsCount.Load()

	// First add a non-strict-egress-policy entry, it should remain untouch
	// during the following sync.
	k.controller.policyMap.Update(
		netip.MustParseAddr(ep2IP),
		strictEgressPolicyValidationDstCIDR,
		netip.MustParseAddr(ep2EgressIP),
		netip.MustParseAddr(ep2GatewayIP),
	)

	// Create a stale strict egress policy entry in the map,
	// we should expect the sync event triggering a reconciliation
	// to remove this stale entry.
	k.controller.policyMap.Update(
		netip.MustParseAddr(ep1IP),
		strictEgressPolicyValidationDstCIDR,
		strictEgressPolicyValidationEgressIP,
		strictEgressPolicyValidationGatewayIP,
	)
	assertEgressRules(t, k.controller.policyMap, []egressRule{ep1EgressRule, ep2EgressRule})
	k.cepResource.sync(t)
	eventCount = waitForReconciliationRun(t, k.controller, eventCount)
	assertEgressRules(t, k.controller.policyMap, []egressRule{ep2EgressRule})

	// Add a new endpoint & ID which matches infra-access rule.
	ep1, _ := newEndpointAndIdentity("ep-1", ep1IP, node1IP, ep1Labels)
	addEndpoint(t, k.cepResource, &ep1)
	eventCount = waitForReconciliationRun(t, k.controller, eventCount)
	assertEgressRules(t, k.controller.policyMap, []egressRule{ep1EgressRule, ep2EgressRule})

	// Manually delete this policy entry, we expect sync() to bring it back.
	k.controller.policyMap.Delete(
		netip.MustParseAddr(ep1IP),
		strictEgressPolicyValidationDstCIDR,
	)
	assertEgressRules(t, k.controller.policyMap, []egressRule{ep2EgressRule})
	k.cepResource.sync(t)
	eventCount = waitForReconciliationRun(t, k.controller, eventCount)
	assertEgressRules(t, k.controller.policyMap, []egressRule{ep1EgressRule, ep2EgressRule})

	// Make this policy entry malformed (wrong gateway IP), expect sync to recover it.
	k.controller.policyMap.Update(
		netip.MustParseAddr(ep1IP),
		strictEgressPolicyValidationDstCIDR,
		strictEgressPolicyValidationEgressIP,
		netip.MustParseAddr("1.2.3.4"),
	)
	assertEgressRules(t, k.controller.policyMap, []egressRule{
		{
			sourceIP:  ep1IP,
			destCIDR:  strictEgressPolicyValidationDstCIDR.String(),
			egressIP:  strictEgressPolicyValidationEgressIP.String(),
			gatewayIP: "1.2.3.4",
		},
		ep2EgressRule,
	})
	k.cepResource.sync(t)
	eventCount = waitForReconciliationRun(t, k.controller, eventCount)
	assertEgressRules(t, k.controller.policyMap, []egressRule{ep1EgressRule, ep2EgressRule})

	// Egress gateway overrided the underlying policy entry, we should not touch it in this case.
	// Similuate the case egressNAT override strict egress policy.
	k.controller.policyMap.Update(
		netip.MustParseAddr(ep1IP),
		strictEgressPolicyValidationDstCIDR,
		netip.MustParseAddr("1.2.3.4"),
		netip.MustParseAddr("2.3.4.5"),
	)
	k.cepResource.sync(t)
	eventCount = waitForReconciliationRun(t, k.controller, eventCount)
	assertEgressRules(t, k.controller.policyMap, []egressRule{
		{
			sourceIP:  ep1IP,
			destCIDR:  strictEgressPolicyValidationDstCIDR.String(),
			egressIP:  "1.2.3.4",
			gatewayIP: "2.3.4.5",
		},
		ep2EgressRule,
	})
}

func TestAddEndpoint(t *testing.T) {
	k := setupControllerTestSuite(t)
	eventCount := k.controller.reconciliationEventsCount.Load()

	// Add a new endpoint & ID which matches infra-access rule.
	ep1, id1 := newEndpointAndIdentity("ep-1", ep1IP, node1IP, ep1Labels)
	addEndpoint(t, k.cepResource, &ep1)
	eventCount = waitForReconciliationRun(t, k.controller, eventCount)
	assertEgressRules(t, k.controller.policyMap, []egressRule{ep1EgressRule})

	// Update the endpoint labels in order for it to not be a match
	id1 = updateEndpointAndIdentity(&ep1, id1, map[string]string{})
	addEndpoint(t, k.cepResource, &ep1)
	eventCount = waitForReconciliationRun(t, k.controller, eventCount)
	assertEgressRules(t, k.controller.policyMap, []egressRule{})

	// Restore the old endpoint lables in order for it to be a match again.
	id1 = updateEndpointAndIdentity(&ep1, id1, ep1Labels)
	addEndpoint(t, k.cepResource, &ep1)
	eventCount = waitForReconciliationRun(t, k.controller, eventCount)
	assertEgressRules(t, k.controller.policyMap, []egressRule{ep1EgressRule})

	// Egress gateway overrided the underlying policy entry, we should not touch it in this case.
	k.controller.policyMap.Update(
		netip.MustParseAddr(ep1IP),
		strictEgressPolicyValidationDstCIDR,
		netip.MustParseAddr("1.2.3.4"),
		netip.MustParseAddr("2.3.4.5"),
	)
	addEndpoint(t, k.cepResource, &ep1)
	eventCount = waitForReconciliationRun(t, k.controller, eventCount)
	assertEgressRules(t, k.controller.policyMap, []egressRule{
		{
			sourceIP:  ep1IP,
			destCIDR:  strictEgressPolicyValidationDstCIDR.String(),
			egressIP:  "1.2.3.4",
			gatewayIP: "2.3.4.5",
		},
	})
}

func TestDeleteEndpoint(t *testing.T) {
	k := setupControllerTestSuite(t)
	eventCount := k.controller.reconciliationEventsCount.Load()

	// Add a new endpoint & ID which matches infra-access rule.
	ep1, _ := newEndpointAndIdentity("ep-1", ep1IP, node1IP, ep1Labels)
	addEndpoint(t, k.cepResource, &ep1)
	eventCount = waitForReconciliationRun(t, k.controller, eventCount)
	assertEgressRules(t, k.controller.policyMap, []egressRule{ep1EgressRule})

	// Delete the endpoint, make sure the egress rule is gone.
	deleteEndpoint(t, k.cepResource, &ep1)
	eventCount = waitForReconciliationRun(t, k.controller, eventCount)
	assertEgressRules(t, k.controller.policyMap, []egressRule{})

	// Add a non-matching endpoint.
	ep1, _ = newEndpointAndIdentity("ep-1", ep1IP, node1IP, map[string]string{})
	addEndpoint(t, k.cepResource, &ep1)
	eventCount = waitForReconciliationRun(t, k.controller, eventCount)
	assertEgressRules(t, k.controller.policyMap, []egressRule{})
	// Delete this non-matching endpoint.
	deleteEndpoint(t, k.cepResource, &ep1)
	eventCount = waitForReconciliationRun(t, k.controller, eventCount)
	assertEgressRules(t, k.controller.policyMap, []egressRule{})

	// Add a policy entry directly into the policy map, without adding the endpoint
	k.controller.policyMap.Update(
		netip.MustParseAddr(ep1IP),
		strictEgressPolicyValidationDstCIDR,
		strictEgressPolicyValidationEgressIP,
		strictEgressPolicyValidationGatewayIP,
	)
	assertEgressRules(t, k.controller.policyMap, []egressRule{ep1EgressRule})
	deleteEndpoint(t, k.cepResource, &ep1)
	eventCount = waitForReconciliationRun(t, k.controller, eventCount)
	assertEgressRules(t, k.controller.policyMap, []egressRule{})
}
