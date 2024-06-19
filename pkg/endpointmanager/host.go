// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package endpointmanager

import (
	v1 "k8s.io/api/core/v1"

	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/node"

	"github.com/cilium/cilium/pkg/comparator"
	"github.com/cilium/cilium/pkg/labelsfilter"
)

// GetHostEndpoint returns the host endpoint.
func (mgr *EndpointManager) GetHostEndpoint() *endpoint.Endpoint {
	mgr.mutex.RLock()
	defer mgr.mutex.RUnlock()
	for _, ep := range mgr.endpoints {
		if ep.IsHost() && ep.IsDefaultHost() {
			return ep
		}
	}
	return nil
}

// HostEndpointExists returns true if the host endpoint exists.
func (mgr *EndpointManager) HostEndpointExists() bool {
	return mgr.GetHostEndpoint() != nil
}

// OnAddNode implements the EndpointManager's logic for reacting to new nodes
// from K8s. It is currently not implemented as the EndpointManager has not
// need for it. This adheres to the subscriber.NodeHandler interface.
func (mgr *EndpointManager) OnAddNode(node *v1.Node,
	swg *lock.StoppableWaitGroup) error {

	return nil
}

// OnUpdateNode implements the EndpointManager's logic for reacting to updated
// nodes in K8s. It is currently not implemented as the EndpointManager has not
// need for it. This adheres to the subscriber.NodeHandler interface.
func (mgr *EndpointManager) OnUpdateNode(oldNode, newNode *v1.Node,
	swg *lock.StoppableWaitGroup) error {

	oldNodeLabels := oldNode.GetLabels()
	newNodeLabels := newNode.GetLabels()

	nodeEP := mgr.GetHostEndpoint()
	if nodeEP == nil {
		log.Error("Host endpoint not found")
		return nil
	}

	node.SetLabels(newNodeLabels)

	newNodeIdtyLabels, _ := labelsfilter.Filter(labels.Map2Labels(newNodeLabels, labels.LabelSourceK8s))
	oldNodeIdtyLabels, _ := labelsfilter.Filter(labels.Map2Labels(oldNodeLabels, labels.LabelSourceK8s))
	if comparator.MapStringEquals(oldNodeIdtyLabels.K8sStringMap(), newNodeIdtyLabels.K8sStringMap()) {
		log.Debug("Host endpoint identity labels unchanged, skipping labels update")
		return nil
	}

	err := nodeEP.UpdateLabelsFrom(oldNodeLabels, newNodeLabels, labels.LabelSourceK8s)
	if err != nil {
		return err
	}

	for _, multinicNodeEP := range mgr.GetMultiNICHostEndpoints() {
		if err := multinicNodeEP.UpdateLabelsFrom(oldNodeLabels, newNodeLabels, labels.LabelSourceK8s); err != nil {
			return err
		}
	}

	return nil
}

// OnDeleteNode implements the EndpointManager's logic for reacting to node
// deletions from K8s. It is currently not implemented as the EndpointManager
// has not need for it. This adheres to the subscriber.NodeHandler interface.
func (mgr *EndpointManager) OnDeleteNode(node *v1.Node,
	swg *lock.StoppableWaitGroup) error {

	return nil
}
