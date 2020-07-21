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

package agent

import (
	"fmt"
	"reflect"
	"sync"
	"time"

	"github.com/cilium/cilium/pkg/gke/nodefirewall/types"
	"github.com/cilium/cilium/pkg/gke/nodefirewall/validation"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/sirupsen/logrus"
	"gke-internal/gke-node-firewall/pkg/apis/nodenetworkpolicy/v1alpha1"
	nnpclient "gke-internal/gke-node-firewall/pkg/client/nodenetworkpolicy/clientset/versioned"
	nnpinformers "gke-internal/gke-node-firewall/pkg/client/nodenetworkpolicy/informers/externalversions"
	apiv1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	corev1 "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/record"
	"k8s.io/klog"

	"github.com/cilium/cilium/pkg/gke/nodefirewall/logging"
	"github.com/cilium/cilium/pkg/gke/nodefirewall/taskqueue"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/metrics"
	ciliumpolicy "github.com/cilium/cilium/pkg/policy"
)

const (
	storeSyncPollPeriod  = 5 * time.Second
	informerResyncPeriod = 10 * time.Minute

	// constants used for events.
	invalidPolicy       = "InvalidPolicy"
	failedToParsePolicy = "FailToParse"
	failedToApplyPolicy = "FailToApply"
)

// NodeFirewallAgent watches the kubernetes API for NodeNetworkPolicy
// resources and programs firewall rules for them.
type NodeFirewallAgent struct {
	// eventRecorder records the controller sync failures.
	// Events are generated only on specific sync failures which needs the user
	// attention to avoid scaling issues.
	eventRecorder record.EventRecorder

	// ciliumPolicyManager manages all firewall policies.
	ciliumPolicyManager types.PolicyManager

	policyInformer cache.SharedIndexInformer
	// hasSynced is function that returns whether all informers are synced.
	hasSynced   func() bool
	policyStore cache.Store

	// queue is a serialized rating limiting queue that enables the controller
	// to sync node network policies one after the other.
	queue taskqueue.TaskQueue

	// stopCh is used for graceful termination of the controller.
	stopCh chan struct{}
	// stopOnce ensures that shutdown is not invoked multiple times.
	stopOnce *sync.Once
}

// NewNodeFirewallAgent creates a controller for NodeNetworkPolicy CRDs.
func NewNodeFirewallAgent(kubeClient kubernetes.Interface, nodeFWClient nnpclient.Interface, ciliumPolicyManager types.PolicyManager) *NodeFirewallAgent {
	broadcaster := record.NewBroadcaster()
	broadcaster.StartLogging(klog.Infof)
	broadcaster.StartRecordingToSink(&corev1.EventSinkImpl{
		Interface: kubeClient.CoreV1().Events(""),
	})

	nc := &NodeFirewallAgent{
		eventRecorder:       broadcaster.NewRecorder(scheme.Scheme, apiv1.EventSource{Component: "anet-node-firewall-agent", Host: nodeTypes.GetName()}),
		policyInformer:      nnpinformers.NewSharedInformerFactory(nodeFWClient, informerResyncPeriod).Networking().V1alpha1().NodeNetworkPolicies().Informer(),
		ciliumPolicyManager: ciliumPolicyManager,
		stopCh:              make(chan struct{}),
		stopOnce:            new(sync.Once),
	}
	nc.policyStore = nc.policyInformer.GetStore()
	nc.queue = taskqueue.NewPeriodicTaskQueue("nodenetworkpolicy", nc.sync)
	nc.hasSynced = nc.policyInformer.HasSynced

	// Node Network Policy event handlers.
	nc.policyInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			addPolicy, ok := objToNodeNetworkPolicy(obj)
			if !ok {
				return
			}
			logging.NodeFWLogger.Infof("NodeNetworkPolicy %v added, enqueuing", addPolicy.Name)
			nc.queue.Enqueue(obj)
		},
		UpdateFunc: func(old, cur interface{}) {
			if reflect.DeepEqual(old, cur) {
				logging.NodeFWLogger.Debugf("Object(type %T) unchanged, ignoring update", cur)
				return
			}
			curPolicy, ok := objToNodeNetworkPolicy(cur)
			if !ok {
				return
			}
			logging.NodeFWLogger.Infof("NodeNetworkPolicy %s changed, enqueuing", curPolicy.Name)
			nc.queue.Enqueue(cur)
		},
		DeleteFunc: func(obj interface{}) {
			delPolicy, ok := objToNodeNetworkPolicy(obj)
			if !ok {
				return
			}
			logging.NodeFWLogger.Infof("NodeNetworkPolicy %v deleted, enqueuing", delPolicy.Name)
			nc.queue.Enqueue(obj)
		},
	})

	return nc
}

// Run starts the controller and waits for stop signal from worker queue.
func (nc *NodeFirewallAgent) Run() {
	logging.NodeFWLogger.Info("Starting NodeNetworkPolicy controller")

	nc.policyInformer.Run(nc.stopCh)
	nc.queue.Run()
}

// Shutdown terminates the controller gracefully.
func (nc *NodeFirewallAgent) Shutdown() {
	nc.stopOnce.Do(func() {
		logging.NodeFWLogger.Info("Shutting down NodeNetworkPolicy Controller")
		close(nc.stopCh)
		nc.queue.Shutdown()
	})
}

func (nc *NodeFirewallAgent) sync(key string) error {
	scopedLog := logging.NodeFWLogger.WithField(logging.NodeNetworkPolicyName, key)
	if !nc.hasSynced() {
		time.Sleep(storeSyncPollPeriod)
		err := fmt.Errorf("waiting for stores to sync")
		scopedLog.Warn(err.Error())
		return err
	}
	scopedLog.Infof("Syncing NodeNetworkPolicy")

	policyObj, exists, err := nc.policyStore.GetByKey(key)
	if err != nil {
		scopedLog.WithError(err).Warnf("Error getting policy with name %s", key)
		return fmt.Errorf("error getting policy for key %s: %v", key, err)
	}
	var policy *v1alpha1.NodeNetworkPolicy
	if exists {
		var ok bool
		policy, ok = objToNodeNetworkPolicy(policyObj)
		if !ok {
			scopedLog.WithError(err).Warnf("Error casting obj %v to policy for key %s", policyObj, key)
			return fmt.Errorf("error casting obj %v to policy for key %s: %v", policyObj, key, err)
		}
		scopedLog = scopedLog.WithField(logfields.K8sAPIVersion, policy.APIVersion)
	}

	if !exists || policy.DeletionTimestamp != nil {
		if !exists {
			scopedLog.Debug("NodeNetworkPolicy not found, deleting")
		}
		policyLabels := getPolicyLabels(key)
		if _, err := nc.ciliumPolicyManager.PolicyDelete(policyLabels); err != nil {
			scopedLog.WithError(err).WithField(logfields.Labels, policyLabels).
				Error("Error deleting NodeNetworkPolicy")
			return err
		}
		scopedLog.Info("NodeNetworkPolicy deleted")
		return nil
	}
	if err := validation.Validate(policy); err != nil {
		nc.eventRecorder.Eventf(policy, apiv1.EventTypeWarning, invalidPolicy, fmt.Sprintf("Failed to validate NodeNetworkPolicy: %v", err))
		scopedLog.WithError(err).WithFields(logrus.Fields{
			logging.NodeNetworkPolicy: logfields.Repr(policy),
		}).Error("Error validating NodeNetworkPolicy")
		return err
	}

	policyRules, err := nnpToCiliumPolicyRules(policy)
	if err != nil {
		nc.eventRecorder.Eventf(policy, apiv1.EventTypeWarning, failedToParsePolicy, fmt.Sprintf("Failed to parse NodeNetworkPolicy: %v", err))
		scopedLog.WithError(err).WithFields(logrus.Fields{
			logging.NodeNetworkPolicy: logfields.Repr(policy),
		}).Error("Error parsing NodeNetworkPolicy")
		return err
	}
	opts := ciliumpolicy.AddOptions{Replace: true, Source: metrics.LabelEventSourceK8s}
	if _, err := nc.ciliumPolicyManager.PolicyAdd(policyRules, &opts); err != nil {
		nc.eventRecorder.Eventf(policy, apiv1.EventTypeWarning, failedToApplyPolicy, fmt.Sprintf("Failed to apply NodeNetworkPolicy: %v", err))
		scopedLog.WithError(err).WithFields(logrus.Fields{
			logging.NodeNetworkPolicy: logfields.Repr(policyRules),
		}).Error("Error adding NodeNetworkPolicy rules to policy repository")
		return err
	}

	scopedLog.Info("NodeNetworkPolicy successfully synced")
	return nil
}
