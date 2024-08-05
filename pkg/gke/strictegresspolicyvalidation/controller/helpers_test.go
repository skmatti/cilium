package controller

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"

	"github.com/cilium/cilium/pkg/identity"
	cilium_api_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slimv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	k8sTypes "github.com/cilium/cilium/pkg/k8s/types"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/maps/egressmap"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sLabels "k8s.io/apimachinery/pkg/labels"
)

func TestGenerateLabelSelectors(t *testing.T) {
	testCases := []struct {
		name              string
		labelSelectorStrs []string
		labelSelectors    []*metav1.LabelSelector
		wantErr           bool
	}{
		{
			name: "infra access label",
			labelSelectorStrs: []string{
				"networking.private.gdc.goog/infra-access=enabled",
			},
			labelSelectors: []*metav1.LabelSelector{
				{
					MatchLabels: map[string]string{
						"networking.private.gdc.goog/infra-access": "enabled",
					},
				},
			},
		},
		{
			name: "multiple access labels",
			labelSelectorStrs: []string{
				"networking.private.gdc.goog/infra-access=enabled",
				"configsync.gke.io/sync-kind=RootSync",
			},
			labelSelectors: []*metav1.LabelSelector{
				{
					MatchLabels: map[string]string{
						"networking.private.gdc.goog/infra-access": "enabled",
					},
				},
				{
					MatchLabels: map[string]string{
						"configsync.gke.io/sync-kind": "RootSync",
					},
				},
			},
		},
		{
			name: "invalid labels",
			labelSelectorStrs: []string{
				`networking.private.gdc.goog/infra-access="enabled"`,
			},
			wantErr: true,
		},
		{
			name: "empty labels and label with empty values",
			labelSelectorStrs: []string{
				``,
				`configsync.gke.io/sync-kind=`,
			},
			labelSelectors: []*metav1.LabelSelector{
				{
					MatchLabels: map[string]string{
						"configsync.gke.io/sync-kind": "",
					},
				},
			},
		},
		{
			name: "no labels",
			labelSelectorStrs: []string{
				``,
			},
			wantErr: true,
		},
		{
			name: "mixed label match and label expressions",
			labelSelectorStrs: []string{
				"networking.private.gdc.goog/infra-access=enabled",
				"configsync.gke.io/sync-kind in (RootSync)",
			},
			labelSelectors: []*metav1.LabelSelector{
				{
					MatchLabels: map[string]string{
						"networking.private.gdc.goog/infra-access": "enabled",
					},
				},
				{
					MatchExpressions: []metav1.LabelSelectorRequirement{
						{
							Key:      "configsync.gke.io/sync-kind",
							Operator: metav1.LabelSelectorOpIn,
							Values:   []string{"RootSync"},
						},
					},
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			labelSelectors, err := generateLabelSelectors(tc.labelSelectorStrs)
			if tc.wantErr != (err != nil) {
				t.Errorf("got error %v, but wantErr is %v", err, tc.wantErr)
			}

			if diff := cmp.Diff(tc.labelSelectors, labelSelectors, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("got different label selectors (-got +want): %s", diff)
			}
		})
	}
}

func TestConvertLabelArrayToK8SLabelSet(t *testing.T) {
	la := labels.LabelArray{
		labels.NewLabel("label1", "1", "k8s"),
		labels.NewLabel("label2", "2", "reserved"),
		labels.NewLabel("1.2.3.4/32", "label3", "cidr"),
	}
	labelSet := convertLabelArrayToK8SLabelSet(la)
	want := k8sLabels.Set{
		"label1": "1",
	}
	if diff := cmp.Diff(want, labelSet); diff != "" {
		t.Errorf("got different label set (-got +want): %s", diff)
	}
}

func TestMatchesAnyLabelSelectors(t *testing.T) {
	testCases := []struct {
		name              string
		labelSelectorStrs []string
		labels            map[string]string
		want              bool
	}{
		{
			name: "match single label",
			labelSelectorStrs: []string{
				"networking.private.gdc.goog/infra-access=enabled",
			},
			labels: map[string]string{
				"networking.private.gdc.goog/infra-access": "enabled",
			},
			want: true,
		},
		{
			name: "match single label",
			labelSelectorStrs: []string{
				"networking.private.gdc.goog/infra-access=enabled",
			},
			labels: map[string]string{},
			want:   false,
		},
		{
			name: "match any of multiple labels",
			labelSelectorStrs: []string{
				"networking.private.gdc.goog/infra-access=enabled",
				"configsync.gke.io/sync-kind=RootSync",
			},
			labels: map[string]string{
				"networking.private.gdc.goog/infra-access": "enabled",
			},
			want: true,
		},
		{
			name: "match any of multiple labels 2",
			labelSelectorStrs: []string{
				"networking.private.gdc.goog/infra-access=enabled",
				"configsync.gke.io/sync-kind=RootSync",
			},
			labels: map[string]string{
				"networking.private.gdc.goog/infra-access": "enabled",
				"configsync.gke.io/sync-kind":              "no-match",
			},
			want: true,
		},
		{
			name: "match none of multiple labels",
			labelSelectorStrs: []string{
				"networking.private.gdc.goog/infra-access=enabled",
				"configsync.gke.io/sync-kind=RootSync",
			},
			labels: map[string]string{
				"networking.private.gdc.goog/infra-access": "disabled",
			},
			want: false,
		},
		{
			name: "match using expression",
			labelSelectorStrs: []string{
				"networking.private.gdc.goog/infra-access=enabled",
				"configsync.gke.io/sync-kind in (RootSync)",
			},
			labels: map[string]string{
				"networking.private.gdc.goog/infra-access": "no-match",
				"configsync.gke.io/sync-kind":              "RootSync",
			},
			want: true,
		},
		{
			name: "match using expression - in",
			labelSelectorStrs: []string{
				"networking.private.gdc.goog/infra-access=enabled",
				"configsync.gke.io/sync-kind notin (RootSync)",
			},
			labels: map[string]string{
				"networking.private.gdc.goog/infra-access": "no-match",
				"configsync.gke.io/sync-kind":              "notin-match",
			},
			want: true,
		},
		{
			name: "match using expression - exists",
			labelSelectorStrs: []string{
				"networking.private.gdc.goog/infra-access=enabled",
				"configsync.gke.io/sync-kind",
			},
			labels: map[string]string{
				"configsync.gke.io/sync-kind": "",
			},
			want: true,
		},
		{
			name: "match using expression - exists",
			labelSelectorStrs: []string{
				"networking.private.gdc.goog/infra-access=enabled",
				"configsync.gke.io/sync-kind",
			},
			labels: map[string]string{
				"configsync.gke.io/sync-kind": "some value",
			},
			want: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			labelSelectors, err := generateLabelSelectors(tc.labelSelectorStrs)
			if err != nil {
				t.Errorf("got error %v", err)
			}

			var accessLabelSelectors []k8sLabels.Selector
			for _, labelSelector := range labelSelectors {
				if selector, err := metav1.LabelSelectorAsSelector(labelSelector); err == nil {
					accessLabelSelectors = append(accessLabelSelectors, selector)
				} else {
					t.Errorf("create label selector: %v", err)
				}
			}

			got := matchesAnyLabelSelectors(accessLabelSelectors, k8sLabels.Set(tc.labels))
			if got != tc.want {
				t.Errorf("got %v, but want %v", got, tc.want)
			}
		})
	}
}

type fakeResource[T runtime.Object] chan resource.Event[T]

func (fr fakeResource[T]) sync(tb testing.TB) {
	var sync resource.Event[T]
	sync.Kind = resource.Sync
	fr.process(tb, sync)
}

func (fr fakeResource[T]) process(tb testing.TB, ev resource.Event[T]) {
	tb.Helper()
	if err := fr.processWithError(ev); err != nil {
		tb.Fatal("Failed to process event:", err)
	}
}

func (fr fakeResource[T]) processWithError(ev resource.Event[T]) error {
	errs := make(chan error)
	ev.Done = func(err error) {
		errs <- err
	}
	fr <- ev
	return <-errs
}

func (fr fakeResource[T]) Observe(ctx context.Context, next func(event resource.Event[T]), complete func(error)) {
	complete(errors.New("not implemented"))
}

func (fr fakeResource[T]) Events(ctx context.Context, opts ...resource.EventsOpt) <-chan resource.Event[T] {
	if len(opts) > 1 {
		// Ideally we'd only ignore resource.WithRateLimit here, but that
		// isn't possible.
		panic("more than one option is not supported")
	}
	return fr
}

func (fr fakeResource[T]) Store(context.Context) (resource.Store[T], error) {
	return nil, errors.New("not implemented")
}

func addEndpoint(tb testing.TB, endpoints fakeResource[*k8sTypes.CiliumEndpoint], ep *k8sTypes.CiliumEndpoint) {
	endpoints.process(tb, resource.Event[*k8sTypes.CiliumEndpoint]{
		Kind:   resource.Upsert,
		Object: ep,
	})
}

func deleteEndpoint(tb testing.TB, endpoints fakeResource[*k8sTypes.CiliumEndpoint], ep *k8sTypes.CiliumEndpoint) {
	endpoints.process(tb, resource.Event[*k8sTypes.CiliumEndpoint]{
		Kind:   resource.Delete,
		Object: ep,
	})
}

// Mock the creation of endpoint and its corresponding identity, returns endpoint and ID.
func newEndpointAndIdentity(name, ip, nodeIP string, epLabelsMap map[string]string) (k8sTypes.CiliumEndpoint, *identity.Identity) {
	epLabels := labels.Map2Labels(epLabelsMap, labels.LabelSourceK8s)
	id, _, _ := identityAllocator.AllocateIdentity(context.Background(), epLabels, true, identity.InvalidIdentity)

	return k8sTypes.CiliumEndpoint{
		ObjectMeta: slimv1.ObjectMeta{
			Name:   name,
			UID:    types.UID(uuid.New().String()),
			Labels: epLabelsMap,
		},
		Identity: &cilium_api_v2.EndpointIdentity{
			ID:     int64(id.ID),
			Labels: epLabels.GetModel(),
		},
		Networking: &cilium_api_v2.EndpointNetworking{
			Addressing: cilium_api_v2.AddressPairList{
				&cilium_api_v2.AddressPair{
					IPV4: ip,
				},
			},
			NodeIP: nodeIP,
		},
	}, id
}

// Mock the update of endpoint and its corresponding identity, with new labels. Returns new ID.
func updateEndpointAndIdentity(endpoint *k8sTypes.CiliumEndpoint, oldID *identity.Identity, newEpLabelsMap map[string]string) *identity.Identity {
	ctx := context.Background()
	newEpLabels := labels.Map2Labels(newEpLabelsMap, labels.LabelSourceK8s)

	identityAllocator.Release(ctx, oldID, true)
	newID, _, _ := identityAllocator.AllocateIdentity(ctx, newEpLabels, true, identity.InvalidIdentity)
	endpoint.Identity.ID = int64(newID.ID)
	endpoint.Labels = newEpLabelsMap
	endpoint.Identity.Labels = newEpLabels.GetModel()
	return newID
}

func parseEgressRule(sourceIP, destCIDR, egressIP, gatewayIP string) parsedEgressRule {
	sip := netip.MustParseAddr(sourceIP)
	dc := netip.MustParsePrefix(destCIDR)
	eip := netip.MustParseAddr(egressIP)
	gip := netip.MustParseAddr(gatewayIP)

	return parsedEgressRule{
		sourceIP:  sip,
		destCIDR:  dc,
		egressIP:  eip,
		gatewayIP: gip,
	}
}

type egressRule struct {
	sourceIP  string
	destCIDR  string
	egressIP  string
	gatewayIP string
}

type parsedEgressRule struct {
	sourceIP  netip.Addr
	destCIDR  netip.Prefix
	egressIP  netip.Addr
	gatewayIP netip.Addr
}

func assertEgressRules(t *testing.T, policyMap egressmap.PolicyMap, rules []egressRule) {
	t.Helper()

	err := tryAssertEgressRules(policyMap, rules)
	require.NoError(t, err)
}

func tryAssertEgressRules(policyMap egressmap.PolicyMap, rules []egressRule) error {
	parsedRules := []parsedEgressRule{}
	for _, r := range rules {
		parsedRules = append(parsedRules, parseEgressRule(r.sourceIP, r.destCIDR, r.egressIP, r.gatewayIP))
	}

	for _, r := range parsedRules {
		policyVal, err := policyMap.Lookup(r.sourceIP, r.destCIDR)
		if err != nil {
			return fmt.Errorf("cannot lookup policy entry: %w", err)
		}

		if policyVal.GetEgressAddr() != r.egressIP {
			return fmt.Errorf("mismatched egress IP for %s, got %s, want %s", r.sourceIP, policyVal.GetEgressAddr(), r.egressIP)
		}

		if policyVal.GetGatewayAddr() != r.gatewayIP {
			return fmt.Errorf("mismatched gateway IP for %s, got %s, want %s", r.sourceIP, policyVal.GetGatewayAddr(), r.gatewayIP)
		}
	}

	untrackedRules := make(map[egressmap.EgressPolicyKey4]egressmap.EgressPolicyVal4)

	policyMap.IterateWithCallback(
		func(key *egressmap.EgressPolicyKey4, val *egressmap.EgressPolicyVal4) {
			for _, r := range parsedRules {
				if key.Match(r.sourceIP, r.destCIDR) && val.Match(r.egressIP, r.gatewayIP) {
					return
				}
			}

			untrackedRules[*key] = *val
		})

	if len(untrackedRules) > 0 {
		return fmt.Errorf("Untracked egress policy: %v", untrackedRules)
	}

	return nil
}

func waitForReconciliationRun(tb testing.TB, c *Controller, currentRun uint64) uint64 {
	for i := 0; i < 100; i++ {
		count := c.reconciliationEventsCount.Load()
		if count > currentRun {
			return count
		}

		time.Sleep(10 * time.Millisecond)
	}

	tb.Fatal("Reconciliation is taking too long to run")
	return 0
}
