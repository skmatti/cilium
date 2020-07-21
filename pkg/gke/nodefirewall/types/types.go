/*
Copyright 2020 Google LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package types

import (
	"net"

	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/policy/api"
)

// Node contains IP and Labels of a k8s node.
type Node struct {
	// IP is the IP address of node.
	IP net.IP
	// Name is the name of node.
	Name string
	// Labels is a map of label
	Labels map[string]string
}

// PolicyManager is interface for adding/deleting the policies from the
// policy repository.
type PolicyManager interface {
	// PolicyAdd adds a slice of rules to the policy repository.
	PolicyAdd(rules api.Rules, opts *policy.AddOptions) (newRev uint64, err error)
	// PolicyAdd deletes the rules associated with given label set from the policy repository.
	PolicyDelete(labels labels.LabelArray) (newRev uint64, err error)
}
