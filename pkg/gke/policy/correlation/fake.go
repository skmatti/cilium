package correlation

import (
	"fmt"

	"github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/pkg/policy/api"
)

var _ Correlator = (*FakePolicyCorrelator)(nil)
var _ Correlator = (*NoopPolicyCorrelator)(nil)

var NoopCorrelator = NoopPolicyCorrelator{}

// NoopPolicyCorrelator is a correlator that returns nil.
type NoopPolicyCorrelator struct{}

// Correlate always returns nil.
func (c *NoopPolicyCorrelator) Correlate(f *flow.Flow) ([]*flow.Policy, error) {
	return nil, nil
}

// NewFakePolicyCorrelator returns a fake correlator for unit testing.
func NewFakePolicyCorrelator(opts ...func(*FakePolicyCorrelator)) *FakePolicyCorrelator {
	f := &FakePolicyCorrelator{
		m: make(map[string]*FakePolicyCorrelatorResult),
	}
	for _, opt := range opts {
		opt(f)
	}
	return f
}

// WithEntry sets the key-value pair on the correlator.
func WithEntry(key string, value *FakePolicyCorrelatorResult) func(*FakePolicyCorrelator) {
	return func(f *FakePolicyCorrelator) {
		f.m[key] = value
	}
}

// FakePolicyCorrelatorResult is used to store the desired result from a Correlate method call.
type FakePolicyCorrelatorResult struct {
	policies []*flow.Policy
	err      error
}

// NewFakePolicyCorrelatorResult is a result which maps to the output from the Correlation metho.
// The base result with no options applied returns a `nil, nil` result.
func NewFakePolicyCorrelatorResult(opts ...func(*FakePolicyCorrelatorResult)) *FakePolicyCorrelatorResult {
	f := &FakePolicyCorrelatorResult{}
	for _, opt := range opts {
		opt(f)
	}
	return f
}

// WithPolicies appends the policies to the result.
func WithPolicies(policies ...*flow.Policy) func(*FakePolicyCorrelatorResult) {
	return func(f *FakePolicyCorrelatorResult) {
		f.policies = append(f.policies, policies...)
	}
}

// WithError sets the error for the result.
func WithError(err error) func(*FakePolicyCorrelatorResult) {
	return func(f *FakePolicyCorrelatorResult) {
		f.err = err
	}
}

// FakePolicyCorrelator implements the Correlator interface.
// It maps the incoming flow to be correlated against a map of result results for the flow.
type FakePolicyCorrelator struct {
	m map[string]*FakePolicyCorrelatorResult
}

// Correlate correlates forwarded flows based on the flow UUID.
func (c *FakePolicyCorrelator) Correlate(f *flow.Flow) ([]*flow.Policy, error) {
	if !api.IsFlowAllowed(f) {
		return nil, nil
	}
	v, ok := c.m[f.Uuid]
	if !ok {
		return nil, fmt.Errorf("Test error: key not found for flow uuid %s", f.Uuid)
	}
	return v.policies, v.err
}
