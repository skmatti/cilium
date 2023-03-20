package policy

import (
	. "gopkg.in/check.v1"

	"github.com/cilium/cilium/pkg/checker"
	"github.com/cilium/cilium/pkg/identity"
	slimmetav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy/api"
)

func (ds *PolicyTestSuite) TestMultiNICHostRuleMatches(c *C) {
	option.Config.EnableGoogleMultiNICHostFirewall = true
	defer func() {
		option.Config.EnableGoogleMultiNICHostFirewall = false
	}()
	testNodeNetwork := "test-node-network-2"
	testMultiNICID := identity.NumericIdentity(144)
	// Use any source to match reserved label.
	policyLabel := labels.NewLabel(labels.IDNameMultiNICHost, testNodeNetwork, labels.LabelSourceAny)
	repo := parseAndAddRules(c, api.Rules{
		&api.Rule{
			NodeSelector: api.NewESFromLabels(policyLabel),
		},
		&api.Rule{
			// Match all endpoints.
			NodeSelector: api.EndpointSelector{
				LabelSelector: &slimmetav1.LabelSelector{},
			},
		},
	})
	multiNIChostRule := repo.rules[0]
	allHostsRule := repo.rules[1]

	// Add multi nic host reserved identity.
	err := identity.InitMultiNICHostNumericIdentitySet(map[string]string{
		testMultiNICID.String(): testNodeNetwork,
	})
	c.Assert(err, IsNil)
	defer func() {
		identity.DeleteReservedIdentity(testMultiNICID)
	}()

	// podIdentity has labels that match both the policy rules -
	// multiNIChostRule and allHostsRule.
	podIdentity := identity.NewIdentity(54321, labels.Labels{policyLabel.Key: policyLabel})

	// host labels does not match multiNIChostRule but matches allHostsRule.
	hostIdentity := identity.NewIdentity(identity.ReservedIdentityHost, labels.LabelHost)

	multiNIChostLabels := labels.NewReservedMultiNICHostLabels(testNodeNetwork)
	multiNIChostLabels.MergeLabels(labels.LabelHost)
	multiNIChostIdentity := identity.NewIdentity(testMultiNICID, multiNIChostLabels)

	// selectedEndpoint is not selected by rule, so it shouldn't be added to EndpointsSelected.
	// Although the labels are matching, this is not host endpoint so rejected.
	c.Assert(multiNIChostRule.matches(podIdentity), Equals, false, Commentf("nodeselector must not match non host identity"))
	c.Assert(multiNIChostRule.metadata.IdentitySelected, checker.DeepEquals, map[identity.NumericIdentity]bool{podIdentity.ID: false})

	// host endpoint is not selected by rule, so it shouldn't be added to EndpointsSelected.
	// Altough this is a host endpoint, the labels are not matching so rejected.
	c.Assert(multiNIChostRule.matches(hostIdentity), Equals, false, Commentf("multi nic host nodeselector must not match the default host identity"))
	c.Assert(multiNIChostRule.metadata.IdentitySelected, checker.DeepEquals, map[identity.NumericIdentity]bool{podIdentity.ID: false, hostIdentity.ID: false})

	// multi nic host endpoint is selected by rule, so it should be added to EndpointsSelected.
	c.Assert(multiNIChostRule.matches(multiNIChostIdentity), Equals, true, Commentf("matching multi nic host identity"))
	c.Assert(multiNIChostRule.metadata.IdentitySelected, checker.DeepEquals,
		map[identity.NumericIdentity]bool{podIdentity.ID: false, hostIdentity.ID: false, multiNIChostIdentity.ID: true})

	// selectedEndpoint is not selected by rule, so it shouldn't be added to EndpointsSelected.
	c.Assert(allHostsRule.matches(podIdentity), Equals, false, Commentf("nodeselector must not match non host identity"))
	c.Assert(allHostsRule.metadata.IdentitySelected, checker.DeepEquals, map[identity.NumericIdentity]bool{podIdentity.ID: false})

	// host endpoint is selected by rule, so it should be added to EndpointsSelected.
	c.Assert(allHostsRule.matches(hostIdentity), Equals, true, Commentf("select-all nodeselector matches the default host identity"))
	c.Assert(allHostsRule.metadata.IdentitySelected, checker.DeepEquals, map[identity.NumericIdentity]bool{podIdentity.ID: false, hostIdentity.ID: true})

	// multi nic host endpoint is selected by rule, so it should be added to EndpointsSelected.
	c.Assert(allHostsRule.matches(multiNIChostIdentity), Equals, true, Commentf("select-all nodeselector matches multi nic host identity"))
	c.Assert(allHostsRule.metadata.IdentitySelected, checker.DeepEquals,
		map[identity.NumericIdentity]bool{podIdentity.ID: false, hostIdentity.ID: true, multiNIChostIdentity.ID: true})
}

func (ds *PolicyTestSuite) TestMultiNiCHostGetMatchingRules(c *C) {
	option.Config.EnableHostFirewall = true
	option.Config.EnableGoogleMultiNICHostFirewall = true
	defer func() {
		option.Config.EnableHostFirewall = false
		option.Config.EnableGoogleMultiNICHostFirewall = false
	}()
	// Cache policy enforcement value from when test was ran to avoid pollution
	// across tests.
	oldPolicyEnable := GetPolicyEnabled()
	defer SetPolicyEnabled(oldPolicyEnable)

	SetPolicyEnabled(option.DefaultEnforcement)

	testNodeNetwork := "test-node-network-4"
	testMultiNICID := identity.NumericIdentity(148)
	repo := NewPolicyRepository(nil, nil, nil)
	repo.selectorCache = testSelectorCache

	// Add multi nic host reserved identity.
	err := identity.InitMultiNICHostNumericIdentitySet(map[string]string{
		testMultiNICID.String(): testNodeNetwork,
	})
	c.Assert(err, IsNil)
	defer func() {
		identity.DeleteReservedIdentity(testMultiNICID)
	}()

	lbls := labels.NewReservedMultiNICHostLabels(testNodeNetwork)
	lbls.MergeLabels(labels.LabelHost)
	testMultiNICIdentity := identity.NewIdentity(testMultiNICID, lbls)
	hostIdentity := identity.NewIdentity(identity.ReservedIdentityHost, labels.LabelHost)

	policySelectorLabel := labels.NewLabel(labels.IDNameMultiNICHost, testNodeNetwork, labels.LabelSourceAny)
	epSelectorRule := api.Rule{
		EndpointSelector: api.NewESFromLabels(policySelectorLabel),
		Ingress: []api.IngressRule{
			{
				IngressCommonRule: api.IngressCommonRule{
					FromEndpoints: []api.EndpointSelector{
						api.NewESFromLabels(labels.ParseSelectLabel("ep-selector-1")),
					},
				},
			},
		},
	}

	multiNICSelectorRule := api.Rule{
		NodeSelector: api.NewESFromLabels(policySelectorLabel),
		Ingress: []api.IngressRule{
			{
				IngressCommonRule: api.IngressCommonRule{
					FromEndpoints: []api.EndpointSelector{
						api.NewESFromLabels(labels.ParseSelectLabel("multi-nic-selector-1")),
					},
				},
			},
		},
	}

	allHostSelectorRule := api.Rule{
		// Select all endpoints.
		NodeSelector: api.NewESFromMatchRequirements(nil, nil),
		Ingress: []api.IngressRule{
			{
				IngressCommonRule: api.IngressCommonRule{
					FromEndpoints: []api.EndpointSelector{
						api.NewESFromLabels(labels.ParseSelectLabel("all-host-selector-1")),
					},
				},
			},
		},
	}

	ing, egr, matchingRules := repo.computePolicyEnforcementAndRules(testMultiNICIdentity)
	c.Assert(ing, Equals, false, Commentf("should not match, no ingress rules are in repository"))
	c.Assert(egr, Equals, false, Commentf("should not match, no egress rules are in repository"))
	c.Assert(matchingRules, checker.DeepEquals, ruleSlice{}, Commentf("returned matching rules did not match"))

	// Add policy rule with endpoint selector to the repository.
	_, _, err = repo.Add(epSelectorRule, []Endpoint{})
	c.Assert(err, IsNil, Commentf("unable to add rule to policy repository"))
	ing, egr, matchingRules = repo.computePolicyEnforcementAndRules(testMultiNICIdentity)
	c.Assert(ing, Equals, false, Commentf("should not match endpoint selector"))
	c.Assert(egr, Equals, false, Commentf("should not match, no egress rules are in repository"))
	c.Assert(matchingRules, checker.DeepEquals, ruleSlice{}, Commentf("returned matching rules did not match"))

	// Add policy rule with multi nic host node selector to the repository.
	_, _, err = repo.Add(multiNICSelectorRule, []Endpoint{})
	c.Assert(err, IsNil, Commentf("unable to add rule to policy repository"))
	ing, egr, matchingRules = repo.computePolicyEnforcementAndRules(testMultiNICIdentity)
	c.Assert(ing, Equals, true, Commentf("should match multi nic selector rule"))
	c.Assert(egr, Equals, false, Commentf("should not match, no egress rules are in repository"))
	c.Assert(matchingRules[0].Rule, checker.DeepEquals, multiNICSelectorRule, Commentf("returned matching rules did not match"))

	// For host identity.
	ing, egr, matchingRules = repo.computePolicyEnforcementAndRules(hostIdentity)
	c.Assert(ing, Equals, false, Commentf("should not match, host identity is not selected by multi nic selector rule"))
	c.Assert(egr, Equals, false, Commentf("should not match, no egress rules are in repository"))
	c.Assert(matchingRules, checker.DeepEquals, ruleSlice{}, Commentf("returned matching rules did not match"))

	// Add policy rule with selct-all node selector to the repository.
	_, _, err = repo.Add(allHostSelectorRule, []Endpoint{})
	c.Assert(err, IsNil, Commentf("unable to add rule to policy repository"))
	ing, egr, matchingRules = repo.computePolicyEnforcementAndRules(testMultiNICIdentity)
	c.Assert(ing, Equals, true, Commentf("should match both selector rules"))
	c.Assert(egr, Equals, false, Commentf("should not match, no egress rules are in repository"))
	c.Assert(matchingRules[0].Rule, checker.DeepEquals, multiNICSelectorRule, Commentf("returned matching rules did not match"))
	c.Assert(matchingRules[1].Rule, checker.DeepEquals, allHostSelectorRule, Commentf("returned matching rules did not match"))

	// For host identity.
	ing, egr, matchingRules = repo.computePolicyEnforcementAndRules(hostIdentity)
	c.Assert(ing, Equals, true, Commentf("should match select-all host rule"))
	c.Assert(egr, Equals, false, Commentf("should not match, no egress rules are in repository"))
	c.Assert(matchingRules[0].Rule, checker.DeepEquals, allHostSelectorRule, Commentf("returned matching rules did not match"))
}
