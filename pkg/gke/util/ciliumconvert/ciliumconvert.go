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

package ciliumconvert

import (
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var (
	log = logging.DefaultLogger.WithField(logfields.LogSubsys, "gke-fqdn-netpol-controller")
)

// SlimLabelSelector converts a Kubernetes LabelSelector to the Cilium slim
// LabelSelector.
func SlimLabelSelector(sel metav1.LabelSelector) slim_metav1.LabelSelector {
	var ml map[string]slim_metav1.MatchLabelsValue
	if len(sel.MatchLabels) > 0 {
		ml = make(map[string]slim_metav1.MatchLabelsValue, len(sel.MatchLabels))
	}
	for k, v := range sel.MatchLabels {
		ml[k] = slim_metav1.MatchLabelsValue(v)
	}

	var me []slim_metav1.LabelSelectorRequirement
	if len(sel.MatchExpressions) > 0 {
		me = make([]slim_metav1.LabelSelectorRequirement, 0, len(sel.MatchExpressions))
	}
	for _, exp := range sel.MatchExpressions {
		var vals []string
		if len(exp.Values) > 0 {
			vals = make([]string, len(exp.Values))
			copy(vals, exp.Values)
		}
		me = append(me, slim_metav1.LabelSelectorRequirement{
			Key:      exp.Key,
			Operator: slim_metav1.LabelSelectorOperator(exp.Operator),
			Values:   vals,
		})
	}
	return slim_metav1.LabelSelector{MatchLabels: ml, MatchExpressions: me}
}
