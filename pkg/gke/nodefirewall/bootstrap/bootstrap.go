// Copyright 2020 Google LLC
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

package bootstrap

import (
	"fmt"

	"gke-internal/gke-node-firewall/pkg/client/nodenetworkpolicy/clientset/versioned"
	"k8s.io/client-go/kubernetes"

	"github.com/cilium/cilium/pkg/gke/nodefirewall/agent"
	"github.com/cilium/cilium/pkg/gke/nodefirewall/logging"
	"github.com/cilium/cilium/pkg/gke/nodefirewall/types"
	"github.com/cilium/cilium/pkg/k8s"
)

func Init(policyManager types.PolicyManager) error {
	logging.NodeFWLogger.Info("Starting node firewall agent")

	kubeConfig, err := k8s.CreateConfig()
	if err != nil {
		return fmt.Errorf("failed to create k8s client rest configuration: %v", err)
	}

	kubeClient, err := kubernetes.NewForConfig(kubeConfig)
	if err != nil {
		return fmt.Errorf("failed to create kuberenetes client: %v", err)
	}

	nodeFirewallClient, err := versioned.NewForConfig(kubeConfig)
	if err != nil {
		return fmt.Errorf("failed to create NodeNetworkPolicy client: %v", err)
	}

	nodeFirewallAgent := agent.NewNodeFirewallAgent(kubeClient, nodeFirewallClient, policyManager)

	go nodeFirewallAgent.Run()
	logging.NodeFWLogger.Info("Node firewall agent started")
	return nil
}
