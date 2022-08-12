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

package controller

import (
	"fmt"
	"time"

	"github.com/cilium/cilium/pkg/gke/apis/fqdnnetworkpolicy/v1alpha1"
	"github.com/cilium/cilium/pkg/gke/client/fqdnnetworkpolicy/clientset/versioned"
	"github.com/cilium/cilium/pkg/gke/client/fqdnnetworkpolicy/informers/externalversions"
	"github.com/cilium/cilium/pkg/k8s"
	k8sUtils "github.com/cilium/cilium/pkg/k8s/utils"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/policy/api"
	"k8s.io/client-go/tools/cache"
)

const (
	defaultResyncPeriod = 10 * time.Minute

	fqdnNetPolNS   = "fqdnNetworkPolicyNamespace"
	fqdnNetPolName = "fqdnNetworkPolicyName"
)

var (
	log = logging.DefaultLogger.WithField(logfields.LogSubsys, "gke-fqdn-netpol-controller")
)

type policyManager interface {
	PolicyAdd(rules api.Rules, opts *policy.AddOptions) (newRev uint64, err error)
	PolicyDelete(labels labels.LabelArray) (newRev uint64, err error)
}

type Controller struct {
	informer cache.SharedIndexInformer
	pm       policyManager

	stopCh chan struct{}
}

func NewController(client versioned.Interface, pm policyManager) *Controller {
	factory := externalversions.NewSharedInformerFactory(client, defaultResyncPeriod)
	informer := factory.Networking().V1alpha1().FQDNNetworkPolicies().Informer()
	c := &Controller{
		informer: informer,
		pm:       pm,
		stopCh:   make(chan struct{}),
	}
	c.informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    func(obj interface{}) { c.addFQDNPolicy(obj) },
		UpdateFunc: func(old, curr interface{}) { c.updateFQDNPolicy(curr) },
		DeleteFunc: func(obj interface{}) { c.deleteFQDNPolicy(obj) },
	})
	return c
}

func (c *Controller) Start() {
	log.Info("Starting FQDN Network Policy Controller")
	go c.informer.Run(c.stopCh)
	if !cache.WaitForNamedCacheSync("fqdnNetworkPolicyController", c.stopCh, c.informer.HasSynced) {
		log.Error("FQDN Network Policy informer failed to sync")
		return
	}

	<-c.stopCh
	log.Info("Shutting down FQDN Network Policy Controller")
}

func objToFQDNNetworkPolicy(obj interface{}) (*v1alpha1.FQDNNetworkPolicy, error) {
	fqdn, ok := obj.(*v1alpha1.FQDNNetworkPolicy)
	if ok {
		return fqdn, nil
	}
	dfsu, ok := obj.(*cache.DeletedFinalStateUnknown)
	if !ok {
		return nil, fmt.Errorf("invalid object type %T", obj)
	}
	fqdn, ok = dfsu.Obj.(*v1alpha1.FQDNNetworkPolicy)
	if !ok {
		return nil, fmt.Errorf("invalid object type in DeletedFinalStateUnknown %T", obj)
	}
	return fqdn, nil
}

func (c *Controller) addFQDNPolicy(obj interface{}) {
	fqdn, err := objToFQDNNetworkPolicy(obj)
	if err != nil {
		log.Errorf("Unable to parse retrieved object: %v", err)
		return
	}
	scopedLog := log.WithField(fqdnNetPolNS, k8sUtils.ExtractNamespaceOrDefault(&fqdn.ObjectMeta))
	scopedLog = scopedLog.WithField(fqdnNetPolName, fqdn.Name)
	scopedLog.Info("Received an add request for FQDN Network Policy")

	c.updatePolicyManager(fqdn)
}

func (c *Controller) updateFQDNPolicy(curr interface{}) {
	fqdn, err := objToFQDNNetworkPolicy(curr)
	if err != nil {
		log.Errorf("Unable to parse retrieved object: %v", err)
		return
	}
	scopedLog := log.WithField(fqdnNetPolNS, k8sUtils.ExtractNamespaceOrDefault(&fqdn.ObjectMeta))
	scopedLog = scopedLog.WithField(fqdnNetPolName, fqdn.Name)
	scopedLog.Info("Received an update request for FQDN Network Policy")

	c.updatePolicyManager(fqdn)
}

func (c *Controller) updatePolicyManager(fqdn *v1alpha1.FQDNNetworkPolicy) {
	scopedLog := log.WithField(fqdnNetPolNS, k8sUtils.ExtractNamespaceOrDefault(&fqdn.ObjectMeta))
	scopedLog = scopedLog.WithField(fqdnNetPolName, fqdn.Name)
	rule, err := parseFQDNNetworkPolicy(fqdn)
	if err != nil {
		scopedLog.Errorf("Error converting FQDN Network Policy: %v", err)
		return
	}
	_, err = c.pm.PolicyAdd(api.Rules{rule}, &policy.AddOptions{Replace: true, Source: metrics.LabelEventSourceK8s})
	if err != nil {
		scopedLog.Errorf("Error adding FQDN Network Policy to policy manager: %v", err)
	} else {
		scopedLog.Info("Updated policy manager with rule")
	}
}

func (c *Controller) deleteFQDNPolicy(obj interface{}) {
	fqdn, err := objToFQDNNetworkPolicy(obj)
	if err != nil {
		log.Errorf("Unable to parse retrieved object: %v", err)
		return
	}

	scopedLog := log.WithField(fqdnNetPolNS, k8sUtils.ExtractNamespaceOrDefault(&fqdn.ObjectMeta))
	scopedLog = scopedLog.WithField(fqdnNetPolName, fqdn.Name)
	scopedLog.Info("Received a delete request for FQDN Network Policy")

	_, err = c.pm.PolicyDelete(policyLabels(fqdn))
	if err != nil {
		scopedLog.Errorf("Error deleting FQDN Network Policy from policy manager: %v", err)
	} else {
		scopedLog.Info("Deleted rule from policy manager")
	}
}

func Init(pm policyManager) (*Controller, error) {
	kubeConfig, err := k8s.CreateConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to create k8s configuration: %v", err)
	}

	fqdnClient, err := versioned.NewForConfig(kubeConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create redirect service client: %v", err)
	}

	c := NewController(fqdnClient, pm)

	go c.Start()
	return c, nil
}
