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

// This file keeps the logic for networkLogging CRD controller.
// It watches the NetworkLogging CRD and make the call
// to configure the loggers.
package controller

import (
	"fmt"
	"time"

	"github.com/cilium/cilium/pkg/gke/apis/networklogging/v1alpha1"
	"github.com/cilium/cilium/pkg/gke/client/networklogging/clientset/versioned"
	"github.com/cilium/cilium/pkg/gke/client/networklogging/informers/externalversions"
	"github.com/cilium/cilium/pkg/gke/dispatcher"
	"github.com/cilium/cilium/pkg/gke/networklogging/policylogger"
	"github.com/cilium/cilium/pkg/hubble/parser/getters"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
)

var (
	log = logging.DefaultLogger.WithField(logfields.LogSubsys, "gke-network-logging-controller")
)

const (

	// informerSyncPeriod is the period to sync with API server
	informerSyncPeriod = 15 * time.Minute

	// This is the only accepted name for NetworkLogging CR.
	networkLoggingResourceName = "default"
)

// Controller for the network logging controller
type Controller struct {
	kubeConfig *rest.Config

	// kubeClient will be used to generate the recorder for events.
	kubeClient kubernetes.Interface

	networkLoggingClient   versioned.Interface
	networkLoggingInformer cache.SharedIndexInformer

	dispatcher     dispatcher.Dispatcher
	endpointGetter getters.EndpointGetter
	storeGetter    getters.StoreGetter
	stopCh         chan struct{}

	policyLogger policylogger.Logger
}

// newController returns a new controller for network logging.
func NewController(kubeConfig *rest.Config, stopCh chan struct{}, dispatcher dispatcher.Dispatcher, endpointGetter getters.EndpointGetter, storeGetter getters.StoreGetter) (*Controller, error) {

	log.Info("New network logging controller")

	kubeClient, err := kubernetes.NewForConfig(kubeConfig)
	if err != nil {
		return nil, fmt.Errorf("Failed to create kube client: %v", err)
	}

	networkLoggingClient, err := versioned.NewForConfig(kubeConfig)
	if err != nil {
		return nil, fmt.Errorf("Failed to create network logging client: %v", err)
	}

	networkLoggingInformerFactory := externalversions.NewSharedInformerFactory(networkLoggingClient, informerSyncPeriod)

	c := &Controller{
		kubeConfig:             kubeConfig,
		kubeClient:             kubeClient,
		networkLoggingClient:   networkLoggingClient,
		networkLoggingInformer: networkLoggingInformerFactory.Networking().V1alpha1().NetworkLoggings().Informer(),
		dispatcher:             dispatcher,
		endpointGetter:         endpointGetter,
		storeGetter:            storeGetter,
		policyLogger:           policylogger.NewLogger(dispatcher, endpointGetter, storeGetter),
		stopCh:                 stopCh,
	}

	c.networkLoggingInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    func(obj interface{}) { c.updateHandler(obj) },
		UpdateFunc: func(old, curr interface{}) { c.updateHandler(curr) },
		DeleteFunc: c.delHandler,
	})
	return c, nil
}

// validateObj validates and converts an object to *v1alpha1.NetworkLogging.
func (c *Controller) validateObj(obj interface{}) (*v1alpha1.NetworkLogging, error) {
	nl, ok := obj.(*v1alpha1.NetworkLogging)
	if !ok {
		return nil, fmt.Errorf("unexpected type %T", obj)
	}

	if nl.Name != networkLoggingResourceName {
		return nl, fmt.Errorf("object name is invalid. Change it to %s.", networkLoggingResourceName)
	}

	return nl, nil
}

// updateHandler handles NetworkLogging CRD add and update events.
func (c *Controller) updateHandler(obj interface{}) {
	o, err := c.validateObj(obj)
	if err != nil {
		log.Errorf("Network logging obj %v is invalid, err %v", obj, err)
		return
	}

	if err, update := c.policyLogger.UpdateLoggingSpec(&o.Spec); err != nil {
		log.Infof("Failed to update network logging cfg: %v, err: %v", o, err)
	} else if update {
		log.Infof("Successfully updated network logging cfg: %v", o.Spec)
	}
	// Todo (b/158724727): Add the state reporting logic.
}

// delHandler handles NetworkLogging CRD delete events.
func (c *Controller) delHandler(obj interface{}) {
	o, ok := obj.(*v1alpha1.NetworkLogging)
	if !ok {
		deletedObj, deletedOk := obj.(cache.DeletedFinalStateUnknown)
		if deletedOk {
			o, ok = deletedObj.Obj.(*v1alpha1.NetworkLogging)
		}
		if !ok {
			log.Warningf("Cannot recover the deleted network logging obj %v", obj)
			return
		}
	}
	// Only do name check and skip the spec check as this is for deletion.
	if o.Name != networkLoggingResourceName {
		return
	}

	log.Infof("Delete network logging obj %v", o)
	if err, _ := c.policyLogger.UpdateLoggingSpec(nil); err != nil {
		log.Infof("Failed to delete network logging cfg %v, err: %v", o, err)
		return
	}
	log.Infof("Delete network logging done")
}

// run starts network logging controller and wait for stop.
func (c *Controller) Run() {
	log.Info("Starting network logging controller")
	go c.networkLoggingInformer.Run(c.stopCh)
	if ok := cache.WaitForNamedCacheSync("networklogging", c.stopCh, c.networkLoggingInformer.HasSynced); !ok {
		log.Error("Failed to wait for networklogging caches to sync")
		return
	}

	<-c.stopCh
	log.Info("Shutting down network logging controller")
	return
}
