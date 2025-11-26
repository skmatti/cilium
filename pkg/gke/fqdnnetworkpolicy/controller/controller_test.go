package controller

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/cilium/cilium/pkg/gke/apis/fqdnnetworkpolicy/v1alpha1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/cilium/cilium/pkg/gke/client/fqdnnetworkpolicy/clientset/versioned/fake"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/policy/api"
)

func TestDeleteFQDNPolicy(t *testing.T) {
	obj := &v1alpha1.FQDNNetworkPolicy{
		ObjectMeta: v1.ObjectMeta{
			Name:      "foo",
			Namespace: "bar",
		},
	}
	lbls := labels.LabelArray(policyLabels(obj))

	f := fake.NewSimpleClientset()
	pm := fakePolicyManager{
		policies: map[string]client.Object{
			lbls.String(): obj,
		},
	}
	c := NewController(f, &pm)

	originalLogger := log.Logger.Out
	defer func() { log.Logger.Out = originalLogger }()
	b := bytes.Buffer{}
	log.Logger.Out = &b

	c.deleteFQDNPolicy(obj)

	s := b.String()
	if !strings.Contains(s, "Deleted rule from policy manager") {
		t.Errorf("Encountered an error while deleting object %T %s: %v", obj, client.ObjectKeyFromObject(obj), s)
	}
}

type fakePolicyManager struct {
	policies       map[string]client.Object
	OnPolicyAdd    func(rules api.Rules, opts *policy.AddOptions) (newRev uint64, err error)
	OnPolicyDelete func(labels labels.LabelArray, opts *policy.DeleteOptions) (newRev uint64, err error)
}

func (f *fakePolicyManager) PolicyAdd(rules api.Rules, opts *policy.AddOptions) (newRev uint64, err error) {
	return 0, nil
}

func (f *fakePolicyManager) PolicyDelete(labels labels.LabelArray, opts *policy.DeleteOptions) (newRev uint64, err error) {
	_, ok := f.policies[labels.String()]
	if !ok {
		return 0, errors.New("not found")
	}
	if opts == nil {
		return 0, errors.New("nil opts")
	}
	delete(f.policies, labels.String())
	return 1, nil
}
