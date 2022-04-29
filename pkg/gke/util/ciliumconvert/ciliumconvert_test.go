// Copyright 2022 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build !privileged_tests
// +build !privileged_tests

package ciliumconvert

import (
	"testing"

	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

func slimLabelSelectorOpts() []cmp.Option {
	labelSelReqLess := func(a, b slim_metav1.LabelSelectorRequirement) bool {
		if a.Key != b.Key {
			return a.Key < b.Key
		}
		if len(a.Values) != len(b.Values) {
			return len(a.Values) < len(b.Values)
		}
		for i := 0; i < len(a.Values); i++ {
			if a.Values[i] != b.Values[i] {
				return a.Values[i] < b.Values[i]
			}
		}
		return string(a.Operator) < string(b.Operator)
	}
	return cmp.Options{
		cmpopts.SortSlices(labelSelReqLess),
	}
}

func TestSlimLabelSelector(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   metav1.LabelSelector
		want slim_metav1.LabelSelector
	}{
		{
			name: "empty selector",
			in:   metav1.LabelSelector{},
			want: slim_metav1.LabelSelector{},
		},
		{
			name: "match labels only",
			in: metav1.LabelSelector{
				MatchLabels: map[string]string{
					"lbl1": "val1",
					"lbl2": "val2",
				},
			},
			want: slim_metav1.LabelSelector{
				MatchLabels: map[string]slim_metav1.MatchLabelsValue{
					"lbl1": slim_metav1.MatchLabelsValue("val1"),
					"lbl2": slim_metav1.MatchLabelsValue("val2"),
				},
			},
		},
		{
			name: "match expression only",
			in: metav1.LabelSelector{
				MatchExpressions: []metav1.LabelSelectorRequirement{
					{Key: "label1", Operator: metav1.LabelSelectorOpExists},
					{Key: "label2", Operator: metav1.LabelSelectorOpDoesNotExist},
					{Key: "label3", Operator: metav1.LabelSelectorOpIn, Values: []string{"opt1", "opt2"}},
					{Key: "label4", Operator: metav1.LabelSelectorOpNotIn, Values: []string{"opt3", "opt4"}},
				},
			},
			want: slim_metav1.LabelSelector{
				MatchExpressions: []slim_metav1.LabelSelectorRequirement{
					{Key: "label1", Operator: slim_metav1.LabelSelectorOpExists},
					{Key: "label2", Operator: slim_metav1.LabelSelectorOpDoesNotExist},
					{Key: "label3", Operator: slim_metav1.LabelSelectorOpIn, Values: []string{"opt1", "opt2"}},
					{Key: "label4", Operator: slim_metav1.LabelSelectorOpNotIn, Values: []string{"opt3", "opt4"}},
				},
			},
		},
		{
			name: "match labels and expression",
			in: metav1.LabelSelector{
				MatchLabels: map[string]string{
					"lbl1": "val1",
					"lbl2": "val2",
				},
				MatchExpressions: []metav1.LabelSelectorRequirement{
					{Key: "label1", Operator: metav1.LabelSelectorOpExists},
					{Key: "label2", Operator: metav1.LabelSelectorOpDoesNotExist},
					{Key: "label3", Operator: metav1.LabelSelectorOpIn, Values: []string{"opt1", "opt2"}},
					{Key: "label4", Operator: metav1.LabelSelectorOpNotIn, Values: []string{"opt3", "opt4"}},
				},
			},
			want: slim_metav1.LabelSelector{
				MatchLabels: map[string]slim_metav1.MatchLabelsValue{
					"lbl1": slim_metav1.MatchLabelsValue("val1"),
					"lbl2": slim_metav1.MatchLabelsValue("val2"),
				},
				MatchExpressions: []slim_metav1.LabelSelectorRequirement{
					{Key: "label1", Operator: slim_metav1.LabelSelectorOpExists},
					{Key: "label2", Operator: slim_metav1.LabelSelectorOpDoesNotExist},
					{Key: "label3", Operator: slim_metav1.LabelSelectorOpIn, Values: []string{"opt1", "opt2"}},
					{Key: "label4", Operator: slim_metav1.LabelSelectorOpNotIn, Values: []string{"opt3", "opt4"}},
				},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := SlimLabelSelector(tc.in)
			if diff := cmp.Diff(tc.want, got, slimLabelSelectorOpts()...); diff != "" {
				t.Fatalf("SlimLabelSelector() had a diff (-want, +got):\n%s", diff)
			}
		})
	}
}
