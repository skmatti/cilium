// Copyright 2023 Google LLC
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
	"github.com/cilium/cilium/pkg/ip"
	"github.com/cilium/cilium/pkg/k8s"
	"net"
	"time"

	"github.com/cilium/cilium/pkg/datapath"
	"github.com/cilium/cilium/pkg/gke/apis/remotenode/v1alpha1"
	"github.com/cilium/cilium/pkg/gke/client/remotenode/clientset/versioned"
	"github.com/cilium/cilium/pkg/gke/client/remotenode/informers/externalversions"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/sirupsen/logrus"
	"k8s.io/client-go/tools/cache"
)

const (
	// UpdateFunc callback is triggered after every defaultResyncPeriod
	defaultResyncPeriod = 2 * time.Hour
)

var (
	log = logging.DefaultLogger.WithField(logfields.LogSubsys, "gke-remotenode-controller")
)

func Init(wgAgent datapath.WireguardAgent, ipcache ipcache) error {
	kubeConfig, err := k8s.CreateConfig()
	if err != nil {
		return fmt.Errorf("failed to create k8s configuration: %v", err)
	}
	clientset, err := versioned.NewForConfig(kubeConfig)
	if err != nil {
		return fmt.Errorf("failed to create remote-node clientset: %v", err)
	}
	c := NewController(clientset, wgAgent, ipcache)
	go c.Start()
	return nil
}

func NewController(clientset *versioned.Clientset, wgAgent datapath.WireguardAgent, ipcache ipcache) *Controller {
	factory := externalversions.NewSharedInformerFactory(clientset, defaultResyncPeriod)
	informer := factory.Networking().V1alpha1().RemoteNodes().Informer()
	c := &Controller{
		informer: informer,
		wgagent:  wgAgent,
		ipcache:  ipcache,
		stopCh:   make(chan struct{}),
	}
	c.informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    func(obj interface{}) { c.onAddRemoteNode(obj) },
		UpdateFunc: func(oldObj, newObj interface{}) { c.onUpdateRemoteNode(newObj) },
		DeleteFunc: func(obj interface{}) { c.onDeleteRemoteNode(obj) },
	})
	return c
}

type ipcache interface {
	UpsertRemotePods(net.IP, []*net.IPNet) error
}

type Controller struct {
	informer cache.SharedIndexInformer
	wgagent  datapath.WireguardAgent
	ipcache  ipcache
	stopCh   chan struct{}
}

func (c *Controller) Start() {
	log.Info("Starting RemoteNode Controller")
	go c.informer.Run(c.stopCh)
	if !cache.WaitForNamedCacheSync("remoteNodeController", c.stopCh, c.informer.HasSynced) {
		log.Errorf("RemoteNode informer failed to sync")
		return
	}
	<-c.stopCh
	log.Info("Shutting down RemoteNode Controller")
}

func (c *Controller) onAddRemoteNode(obj interface{}) {
	remoteNode, err := objToRemoteNode(obj)
	if err != nil {
		log.Errorf("Failed to parse RemoteNode from retrieved object: %v", err)
		return
	}
	log.WithFields(logrus.Fields{
		"name":     remoteNode.Name,
		"ip":       remoteNode.Spec.TunnelIP,
		"pubkey":   remoteNode.Spec.PublicKey,
		"podcidrs": remoteNode.Spec.PodCIDRs,
	}).Info("Will configure wireguard tunnel with remote node")
	c.upsertWireguardTunnel(remoteNode)
}

func (c *Controller) onUpdateRemoteNode(newObj interface{}) {
	remoteNode, err := objToRemoteNode(newObj)
	if err != nil {
		log.Errorf("Failed to parse RemoteNode from retrieved object: %v", err)
		return
	}
	log.WithFields(logrus.Fields{
		"name":     remoteNode.Name,
		"ip":       remoteNode.Spec.TunnelIP,
		"pubkey":   remoteNode.Spec.PublicKey,
		"podcidrs": remoteNode.Spec.PodCIDRs,
	}).Info("Will re-configure wireguard peer config for remote node")
	err = c.upsertWireguardTunnel(remoteNode)
	if err != nil {
		log.WithField("name", remoteNode.Name).Errorf("Failed to re-configure wireguard peer config for remote node: %v", err)
	}
}

func (c *Controller) upsertWireguardTunnel(remoteNode *v1alpha1.RemoteNode) error {
	remoteNodeIP := net.ParseIP(remoteNode.Spec.TunnelIP)
	if remoteNodeIP == nil {
		return fmt.Errorf("failed to parse RemoteNode Tunnel-IP: %s", remoteNode.Spec.TunnelIP)
	}
	var remoteNodeIPv4, remoteNodeIPv6 net.IP
	if ip.IsIPv4(remoteNodeIP) {
		remoteNodeIPv4 = remoteNodeIP
	} else if ip.IsIPv6(remoteNodeIP) {
		remoteNodeIPv6 = remoteNodeIP
	}
	if remoteNodeIPv4 == nil && remoteNodeIPv6 == nil {
		return fmt.Errorf("RemoteNode Tunnel-IP is neither v4 nor v6: %v", remoteNodeIP.String())
	}

	if len(remoteNode.Spec.PodCIDRs) == 0 {
		return fmt.Errorf("RemoteNode Pod-CIDRs cannot be empty")
	}

	var cidrs []*net.IPNet = nil
	for _, s := range remoteNode.Spec.PodCIDRs {
		_, cidr, err := net.ParseCIDR(s)
		if err != nil {
			return fmt.Errorf("failed to parse RemoteNode Pod-CIDR %s: %v", s, err)
		}
		cidrs = append(cidrs, cidr)
	}

	// This populates the pod-cidr of the remote-node into ipcache.
	// This is needed for setting up wireguard peer config.
	// Wireguard uses this info to decide which tunnel to send the traffic on.
	if err := c.ipcache.UpsertRemotePods(remoteNodeIP, cidrs); err != nil {
		return fmt.Errorf("failed to upsert RemoteNode pod-cidr into ipcache")
	}

	// Setup wireguard peer config for this remote-node.
	if err := c.wgagent.UpdatePeer(remoteNode.Name, remoteNode.Spec.PublicKey, remoteNodeIPv4, remoteNodeIPv6); err != nil {
		// TODO(ambekara) - Delete pod-cidr from ipcache.
		return fmt.Errorf("failed to upsert wireguard peer config: %v", err)
	}

	return nil
}

func (c *Controller) onDeleteRemoteNode(obj interface{}) {
	remoteNode, err := objToRemoteNode(obj)
	if err != nil {
		log.Errorf("Failed to parse RemoteNode from retrieved object: %v", err)
		return
	}
	log.WithFields(logrus.Fields{
		"name":     remoteNode.Name,
		"ip":       remoteNode.Spec.TunnelIP,
		"pubkey":   remoteNode.Spec.PublicKey,
		"podcidrs": remoteNode.Spec.PodCIDRs,
	}).Info("Will remove wireguard peer config for remote node")
	if err := c.wgagent.DeletePeer(remoteNode.Name); err != nil {
		log.WithField("name", remoteNode.Name).Errorf("Failed to delete wireguard peer config for remote node: %v", err)
		return
	}
	// TODO(ambekara) - Delete pod-cidr from ipcache.
}

func objToRemoteNode(obj interface{}) (*v1alpha1.RemoteNode, error) {
	switch concreteObj := obj.(type) {
	case *v1alpha1.RemoteNode:
		return concreteObj, nil
	case cache.DeletedFinalStateUnknown:
		remoteNode, ok := concreteObj.Obj.(*v1alpha1.RemoteNode)
		if !ok {
			return nil, fmt.Errorf("invalid object type in DeleteFinalStateUnknown %T", obj)
		}
		return remoteNode, nil
	default:
		return nil, fmt.Errorf("invalid object type %T", obj)
	}
}
