package policy

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy/api"
)

func TestMultiNiCHostGetMatchingRules(t *testing.T) {
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

	td := newTestData()
	repo := td.repo

	testNodeNetwork := "test-node-network-4"
	testMultiNICID := identity.NumericIdentity(148)

	// Add multi nic host reserved identity.
	err := identity.InitMultiNICHostNumericIdentitySet(map[string]string{
		testMultiNICID.String(): testNodeNetwork,
	})
	require.NoError(t, err)
	defer identity.DeleteReservedIdentity(testMultiNICID)

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
	epSelectorRule.Sanitize()

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
	multiNICSelectorRule.Sanitize()

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
	allHostSelectorRule.Sanitize()

	ing, egr, _, _, matchingRules := repo.computePolicyEnforcementAndRules(testMultiNICIdentity)
	require.Equal(t, false, ing, "should not match, no ingress rules are in repository")
	require.Equal(t, false, egr, "should not match, no egress rules are in repository")
	require.Equal(t, ruleSlice{}, matchingRules, "returned matching rules did not match")

	// Add policy rule with endpoint selector to the repository.
	_, _, err = repo.mustAdd(epSelectorRule)
	require.NoError(t, err, "unable to add rule to policy repository")
	ing, egr, _, _, matchingRules = repo.computePolicyEnforcementAndRules(testMultiNICIdentity)
	require.Equal(t, false, ing, "should not match endpoint selector")
	require.Equal(t, false, egr, "should not match, no egress rules are in repository")
	require.Equal(t, ruleSlice{}, matchingRules, "returned matching rules did not match")

	// Add policy rule with multi nic host node selector to the repository.
	_, _, err = repo.mustAdd(multiNICSelectorRule)
	require.NoError(t, err, "unable to add rule to policy repository")
	ing, egr, _, _, matchingRules = repo.computePolicyEnforcementAndRules(testMultiNICIdentity)
	require.Equal(t, true, ing, "should match multi nic selector rule")
	require.Equal(t, false, egr, "should not match, no egress rules are in repository")
	require.Equal(t, multiNICSelectorRule, matchingRules[0].Rule, "returned matching rules did not match")

	// For host identity.
	ing, egr, _, _, matchingRules = repo.computePolicyEnforcementAndRules(hostIdentity)
	require.Equal(t, false, ing, "should not match, host identity is not selected by multi nic selector rule")
	require.Equal(t, false, egr, "should not match, no egress rules are in repository")
	require.Equal(t, ruleSlice{}, matchingRules, "returned matching rules did not match")

	// Add policy rule with selct-all node selector to the repository.
	_, _, err = repo.mustAdd(allHostSelectorRule)
	require.NoError(t, err, "unable to add rule to policy repository")
	ing, egr, _, _, matchingRules = repo.computePolicyEnforcementAndRules(testMultiNICIdentity)
	require.Equal(t, true, ing, "should match both selector rules")
	require.Equal(t, false, egr, "should not match, no egress rules are in repository")
	require.ElementsMatch(t, matchingRules.AsPolicyRules(), api.Rules{&multiNICSelectorRule, &allHostSelectorRule}, "returned matching rules did not match")

	// For host identity.
	ing, egr, _, _, matchingRules = repo.computePolicyEnforcementAndRules(hostIdentity)
	require.Equal(t, true, ing, "should match select-all host rule")
	require.Equal(t, false, egr, "should not match, no egress rules are in repository")
	require.Equal(t, allHostSelectorRule, matchingRules[0].Rule, "returned matching rules did not match")
}
