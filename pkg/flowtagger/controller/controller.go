// Copyright 2025 Google LLC
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

// This file keeps the logic for flowtaggers CRD controller.
// It watches the flowtaggers CRD and updates the eBPF map for the
// dataplane to tag it accordingly.
package controller

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"reflect"
	"sync"

	consts "github.com/cilium/cilium/pkg/k8s/constants"

	"github.com/cilium/cilium/pkg/ebpf"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/client/clientset/versioned"
	"github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/scheme"
	"github.com/cilium/cilium/pkg/k8s/client/informers/externalversions"
	v1 "k8s.io/api/core/v1"
	v1core "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/record"
	"k8s.io/klog/v2"

	"github.com/cilium/cilium/pkg/flowtagger/logging"
	"github.com/cilium/cilium/pkg/flowtagger/queue"
	ftmap "github.com/cilium/cilium/pkg/maps/google_traffictagmap"
	"github.com/cilium/cilium/pkg/time"
)

const (
	tokenRate            = 50
	tokenBurst           = 100
	baseDelay            = 1 * time.Second
	maxDelay             = 100 * time.Second
	informerSyncPeriod   = 5 * time.Minute
	deleteKeyError       = "DeleteKeyError"
	updateKeyError       = "UpdateKeyError"
	createKeyError       = "CreateKeyError"
	lookupKeyError       = "LookupKeyError"
	verifyCollisionError = "VerifyCollisionError"
	validationError      = "ValidationError"
	storeSyncPollPeriod  = 5 * time.Second
	loggerFieldKey       = "FlowTagger"
)

type PacketTaggingKVPair struct {
	Key   ftmap.PacketTaggingKey
	Value ftmap.PacketTaggingValue
}

type Controller struct {
	flowtaggerInformer cache.SharedIndexInformer
	eventRecorder      record.EventRecorder
	NodeName           string
	stopCh             chan struct{}
	stopOnce           *sync.Once

	ftReconcileQueue *queue.FtReconcileQueue
}

// NewController return a flowtagger controller
func NewController(clientset k8sClient.Clientset, flowtaggerClient versioned.Interface, opts ...func(*Controller)) *Controller {
	broadcaster := record.NewBroadcaster()
	broadcaster.StartLogging(klog.Infof)
	broadcaster.StartRecordingToSink(&v1core.EventSinkImpl{Interface: clientset.CoreV1().Events("")})
	recorder := broadcaster.NewRecorder(scheme.Scheme, v1.EventSource{Component: "flow-tagger-controller"})
	flowtaggerInformerFactory := externalversions.NewSharedInformerFactory(flowtaggerClient, informerSyncPeriod)

	nodeName := os.Getenv(consts.EnvNodeNameSpec)
	if nodeName == "" {
		logging.FtLogger.Warnf("Found empty node name from environment variable: %s", consts.EnvNodeNameSpec)
	}

	c := &Controller{
		flowtaggerInformer: flowtaggerInformerFactory.Cilium().V2alpha1().FlowTaggers().Informer(),
		eventRecorder:      recorder,
		NodeName:           nodeName,
		stopCh:             make(chan struct{}),
		stopOnce:           new(sync.Once),
	}
	for _, opt := range opts {
		opt(c)
	}

	c.ftReconcileQueue = queue.NewFtReconcileQueue("flowtagger", c.sync)
	c.flowtaggerInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			key, err := cache.MetaNamespaceKeyFunc(obj)
			if err != nil {
				logging.FtLogger.Errorf("Couldn't get key for object %+v (type %T): %v", obj, obj, err)
				return
			}
			ftKey := queue.FtKey{
				Key:       key,
				Operation: queue.CREATE,
			}
			c.ftReconcileQueue.Enqueue(ftKey)
		},
		UpdateFunc: func(old, cur interface{}) {
			if reflect.DeepEqual(old, cur) {
				logging.FtLogger.Debugf("Object(type %T) unchanged, ignoring update", cur)
				return
			}
			key, err := cache.MetaNamespaceKeyFunc(cur)
			if err != nil {
				logging.FtLogger.Errorf("Couldn't get key for object %+v (type %T): %v", cur, cur, err)
				return
			}
			ftKey := queue.FtKey{
				Key:       key,
				Operation: queue.UPDATE,
				OldFt:     old,
			}
			c.ftReconcileQueue.Enqueue(ftKey)
		},
		DeleteFunc: func(old interface{}) {
			key, err := cache.DeletionHandlingMetaNamespaceKeyFunc(old)
			if err != nil {
				logging.FtLogger.Errorf("Couldn't get key for object %+v (type %T): %v", old, old, err)
				return
			}
			ftKey := queue.FtKey{
				Key:       key,
				Operation: queue.DELETE,
				OldFt:     old,
			}
			c.ftReconcileQueue.Enqueue(ftKey)
		},
	})
	return c
}

// Start runs the flowtagger informer and reloads the existing flowtagger CRs available in the cluster
func (c *Controller) Start(ctx context.Context) {
	logging.FtLogger.Info("Starting FlowTagger controller")
	go c.flowtaggerInformer.Run(c.stopCh)
	if ok := cache.WaitForNamedCacheSync("flowtaggers", ctx.Done(), c.flowtaggerInformer.HasSynced); !ok {
		logging.FtLogger.Error("Failed to wait for flowtaggers caches to sync")
		return
	}
	go c.ftReconcileQueue.Run()
	c.reloadFlowTaggers()
}

// Stop terminates the controller gracefully.
func (c *Controller) Stop() {
	c.stopOnce.Do(func() {
		logging.FtLogger.Info("Shutting down flowtaggers controller")
		close(c.stopCh)
		c.ftReconcileQueue.Shutdown()
	})

}

func (c *Controller) sync(key queue.FtKey) error {
	scopedLog := logging.FtLogger.WithField(loggerFieldKey, key)
	if !c.flowtaggerInformer.HasSynced() {
		time.Sleep(storeSyncPollPeriod)
		err := fmt.Errorf("waiting for stores to sync")
		scopedLog.Warn(err.Error())
		return err
	}

	scopedLog.Info("Syncing FlowTagger")
	ftObj, exists, err := c.flowtaggerInformer.GetStore().GetByKey(key.Key)
	if err != nil {
		scopedLog.WithError(err).Warnf("Error getting FlowTagger with name %s", key.Key)
		return fmt.Errorf("error getting FlowTagger for key %s: %v", key.Key, err)
	}
	// If the object doesn't exist in the store, it might have been deleted.
	// In case of a DELETE operation, the old object is available in key.OldFt.
	if !exists && key.Operation == queue.DELETE && key.OldFt != nil {
		ftObj = key.OldFt
		exists = true
	}
	if !exists {
		scopedLog.Warnf("FlowTagger does not exist with key: %s", key.Key)
		return nil
	}

	// in case of invalid FlowTagger object there is no need to requeue the
	// object again
	ft, err := c.validateObj(ftObj)
	if err != nil {
		scopedLog.WithError(err).Error("Error validating FlowTagger")
		return nil
	}
	var oldFt *v2alpha1.FlowTagger
	if key.OldFt != nil {
		oldFt, err = c.validateObj(key.OldFt)
		if err != nil {
			scopedLog.WithError(err).Warn("Error validating FlowTagger")
			oldFt = nil // disregard old object if it's invalid
		}
	}
	switch key.Operation {
	case queue.CREATE:
		return c.createHandler(ft)
	case queue.UPDATE:
		return c.updateHandler(oldFt, ft)
	case queue.DELETE:
		return c.deleteHandler(ft)
	default:
		scopedLog.Errorf("Unknown operation %v for key %s", key.Operation, key.Key)
	}
	return nil
}

// createHandler creates new eBPF map keys based on the current FlowTagger
func (c *Controller) createHandler(ft *v2alpha1.FlowTagger) error {
	packetTaggingPair := c.getPacketTaggingPairFromFt(ft)

	// a FlowTagger with key which already exists is going to
	// override the previous FlowTagger generated key, to avoid
	// this, key is not created for the current FlowTagger object.
	collidingFtName, err := c.checkFtKeyCollision(ft)
	if err != nil {
		c.eventRecorder.Eventf(ft, v1.EventTypeWarning, verifyCollisionError, "unable to verify key collision against existing FlowTaggers: %v at node: %s", packetTaggingPair.Key, c.NodeName)
		return fmt.Errorf("verify collision for FlowTagger %v: %v", ft.Name, err)
	}
	if collidingFtName != "" {
		c.eventRecorder.Eventf(ft, v1.EventTypeWarning, verifyCollisionError, "key collision with an existing FlowTagger %v at node: %s", collidingFtName, c.NodeName)
		return fmt.Errorf("cannot create Flowtagger %v because key is colliding with an existing FlowTagger %v ", ft.Name, collidingFtName)
	}

	if err := c.updateKey(packetTaggingPair.Key, packetTaggingPair.Value); err != nil {
		c.eventRecorder.Eventf(ft, v1.EventTypeWarning, createKeyError, "unable to update key: %v at node: %s", packetTaggingPair.Key, c.NodeName)
		return fmt.Errorf("create %v ebpf map keys for FlowTagger %v: %v", ftmap.Name, ft.Name, err)
	}
	return nil
}

// updateHandler updates new eBPF map keys based on the current FlowTagger
// to avoid unwanted ip-option tracing old FlowTagger keys must be deleted
func (c *Controller) updateHandler(oldFt, ft *v2alpha1.FlowTagger) error {
	packetTaggingPair := c.getPacketTaggingPairFromFt(ft)
	oldPacketTaggingPair := c.getPacketTaggingPairFromFt(oldFt)

	// if key-value pair remain the same as the old FlowTagger and key-value
	// pair exists in the map as well then no eBPF map update is required.
	exist, value, err := c.keyExists(packetTaggingPair.Key)
	if err != nil {
		c.eventRecorder.Eventf(ft, v1.EventTypeWarning, lookupKeyError, "unable to lookup key: %v at node: %s", packetTaggingPair.Key, c.NodeName)
		return fmt.Errorf("lookup %v ebpf map keys for FlowTagger %v: %v", ftmap.Name, ft.Name, err)
	}
	if oldPacketTaggingPair == packetTaggingPair && exist && value == packetTaggingPair.Value {
		logging.FtLogger.Info("ignoring eBPF map update, updatekey value pair for the current and previous FlowTagger is same")
		return nil
	}

	if oldPacketTaggingPair.Key != packetTaggingPair.Key {
		// key from the updated FlowTagger should not collide with the keys
		// from existing FlowTaggers
		collidingFtName, err := c.checkFtKeyCollision(ft)
		if err != nil {
			c.eventRecorder.Eventf(ft, v1.EventTypeWarning, verifyCollisionError, "unable to verify key collision against existing FlowTaggers: %v at node: %s", packetTaggingPair.Key, c.NodeName)
			return fmt.Errorf("verify collision for FlowTagger %v: %v", ft.Name, err)
		}
		if collidingFtName != "" {
			c.eventRecorder.Eventf(ft, v1.EventTypeWarning, verifyCollisionError, "key collision with an existing FlowTagger %v at node: %s", collidingFtName, c.NodeName)
			return fmt.Errorf("cannot create Flowtagger %v because key is colliding with an existing FlowTagger %v ", ft.Name, collidingFtName)
		}

		if err := c.deleteKey(oldPacketTaggingPair.Key); err != nil {
			c.eventRecorder.Eventf(ft, v1.EventTypeWarning, deleteKeyError, "unable to delete old key: %v at node: %s", oldPacketTaggingPair.Key, c.NodeName)
			return fmt.Errorf("delete %v eBPF map keys for FlowTagger %v: %v", ftmap.Name, ft.Name, err)
		}
	}
	if err := c.updateKey(packetTaggingPair.Key, packetTaggingPair.Value); err != nil {
		c.eventRecorder.Eventf(ft, v1.EventTypeWarning, updateKeyError, "unable to update keys: %v at node: %s", packetTaggingPair.Key, c.NodeName)
		return fmt.Errorf("update %v eBPF map keys for FlowTagger %v: %v", ftmap.Name, ft.Name, err)
	}
	return nil
}

// deleteHandler deletes eBPF map keys based on the deleted FlowTagger
func (c *Controller) deleteHandler(ft *v2alpha1.FlowTagger) error {
	packetTaggingPair := c.getPacketTaggingPairFromFt(ft)
	if err := c.deleteKey(packetTaggingPair.Key); err != nil {
		return fmt.Errorf("delete %v eBPF map keys for FlowTagger %v: %v", ftmap.Name, ft.Name, err)
	}
	return nil
}

func (c *Controller) getPacketTaggingPairFromFt(ft *v2alpha1.FlowTagger) PacketTaggingKVPair {
	if ft == nil {
		return PacketTaggingKVPair{}
	}

	key := ftmap.PacketTaggingKey{
		SourceIP:        ft.Spec.Source.IP,
		SourcePort:      ft.Spec.Source.Port,
		DestinationIP:   ft.Spec.Destination.IP,
		DestinationPort: ft.Spec.Destination.Port,
		Protocol:        ft.Spec.Protocol,
	}
	value := ftmap.PacketTaggingValue{
		TraceID: uint16(ft.Spec.TraceID),
	}

	return PacketTaggingKVPair{Key: key, Value: value}
}

func (c *Controller) updateKey(key ftmap.PacketTaggingKey, value ftmap.PacketTaggingValue) error {
	if err := ftmap.TrafficTagMap.Update(key, value); err != nil {
		return fmt.Errorf("update key %v: %w", key, err)
	}
	return nil
}

func (c *Controller) deleteKey(key ftmap.PacketTaggingKey) error {
	// ignore KeyNotExist error
	if err := ftmap.TrafficTagMap.Delete(key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return fmt.Errorf("delete key %v: %w", key, err)
	}
	return nil
}

// keyExists return true and the value against the key if key exits
// otherwise false, in case of lookup failure, an error is return as well
func (c *Controller) keyExists(key ftmap.PacketTaggingKey) (bool, ftmap.PacketTaggingValue, error) {
	value, err := ftmap.TrafficTagMap.Lookup(key)
	if err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return false, ftmap.PacketTaggingValue{}, nil
		}
		return false, ftmap.PacketTaggingValue{}, err
	}
	return true, value, nil
}

// reloadFlowTaggers tries to delete all existing entries from the eBPF map
// and enqueues the FlowTagger from the cache
func (c *Controller) reloadFlowTaggers() {
	logging.FtLogger.Info("Reloading all FlowTagger")
	if err := ftmap.TrafficTagMap.EmptyMap(); err != nil {
		logging.FtLogger.WithError(err).Warn("Error emptying map")
	}
	for _, obj := range c.flowtaggerInformer.GetStore().List() {
		key, err := cache.MetaNamespaceKeyFunc(obj)
		if err != nil {
			logging.FtLogger.WithError(err).Errorf("Couldn't get key for object %+v (type %T)", obj, obj)
			continue
		}
		ftKey := queue.FtKey{
			Key:       key,
			Operation: queue.CREATE,
		}
		c.ftReconcileQueue.Enqueue(ftKey)
	}
}

func (c *Controller) validateObj(obj interface{}) (*v2alpha1.FlowTagger, error) {
	ft, ok := obj.(*v2alpha1.FlowTagger)
	if !ok {
		deletedObj, deletedOk := obj.(cache.DeletedFinalStateUnknown)
		if deletedOk {
			ft, ok = deletedObj.Obj.(*v2alpha1.FlowTagger)
		}
		if !ok {
			return nil, fmt.Errorf("error casting obj %v to FlowTagger", obj)
		}
	}
	// validate either source or destination is present
	if reflect.DeepEqual(ft.Spec.Source, v2alpha1.FlowTaggerEntity{}) &&
		reflect.DeepEqual(ft.Spec.Destination, v2alpha1.FlowTaggerEntity{}) {
		err := fmt.Errorf("invalid FlowTagger object: %s, either source or destination must be provided", ft.Name)
		c.eventRecorder.Eventf(ft, v1.EventTypeWarning, validationError, err.Error())
		return nil, err
	}
	// validate source FlowTagger Entity
	if err := validateEntity(ft.Spec.Source); err != nil {
		err = fmt.Errorf("invalid FlowTagger object %s, validation failed for source entity: %v", ft.Name, err)
		c.eventRecorder.Eventf(ft, v1.EventTypeWarning, validationError, err.Error())
		return nil, err
	}
	// validate destination FlowTagger Entity
	if err := validateEntity(ft.Spec.Destination); err != nil {
		err = fmt.Errorf("invalid FlowTagger object %s validation failed for source entity: %v", ft.Name, err)
		c.eventRecorder.Eventf(ft, v1.EventTypeWarning, validationError, err.Error())
		return nil, err
	}
	// validate traceId
	if err := validateTraceId(ft.Spec.TraceID); err != nil {
		err = fmt.Errorf("invalid FlowTagger object %s validation failed for traceId: %v", ft.Name, err)
		c.eventRecorder.Eventf(ft, v1.EventTypeWarning, validationError, err.Error())
		return nil, err
	}

	// validate protocol field
	if err := validateProtocol(ft.Spec.Protocol); err != nil {
		err = fmt.Errorf("invalid FlowTagger object %s validation failed for protocol: %v", ft.Name, err)
		c.eventRecorder.Eventf(ft, v1.EventTypeWarning, validationError, err.Error())
		return nil, err
	}
	return ft, nil
}

// checkFtKeyCollision returns the name of the FlowTagger which has the
// same key as the provided FlowTagger. If there is no collision then an
// empty string is returned with nil error. In case of an error and empty
// string is return with the error encountered.
func (c *Controller) checkFtKeyCollision(currentFt *v2alpha1.FlowTagger) (string, error) {
	currentPacketTaggingPair := c.getPacketTaggingPairFromFt(currentFt)
	exist, _, err := c.keyExists(currentPacketTaggingPair.Key)
	if err != nil {
		c.eventRecorder.Eventf(currentFt, v1.EventTypeWarning, lookupKeyError, "unable to lookup key: %v at node: %s", currentPacketTaggingPair.Key, c.NodeName)
		return "", fmt.Errorf("lookup %v ebpf map keys for FlowTagger %v: %v", ftmap.Name, currentFt.Name, err)
	}
	if !exist {
		return "", nil
	}
	ftObjs := c.flowtaggerInformer.GetStore().List()
	for _, obj := range ftObjs {
		ft, ok := obj.(*v2alpha1.FlowTagger)
		if !ok {
			return "", fmt.Errorf("error casting obj %v to FlowTagger", obj)
		}
		if ft.Name == currentFt.Name {
			continue
		}
		packetTaggingPair := c.getPacketTaggingPairFromFt(ft)
		if currentPacketTaggingPair.Key == packetTaggingPair.Key {
			return ft.Name, nil
		}
	}
	return "", nil
}

func validateEntity(entity v2alpha1.FlowTaggerEntity) error {
	if !reflect.DeepEqual(entity, v2alpha1.FlowTaggerEntity{}) {
		if err := validateIp(entity.IP); err != nil {
			return fmt.Errorf("invalid FlowTagger Enity ip: %w", err)
		}
	}
	return nil
}

func validateIp(ip string) error {
	if ip == "" {
		return nil
	}
	if net.ParseIP(ip) == nil {
		return fmt.Errorf("invalid IP address format: %q", ip)
	}
	return nil
}

func validateTraceId(traceId int32) error {
	if traceId <= 0 || traceId > 65535 {
		return fmt.Errorf("traceId should be in range [1,65535]")
	}
	return nil
}

func validateProtocol(protocol v2alpha1.FlowTaggerProtocol) error {
	switch protocol {
	case v2alpha1.FlowTaggerProtocolTCP, v2alpha1.FlowTaggerProtocolUDP, v2alpha1.FlowTaggerProtocolALL:
		return nil
	default:
		return fmt.Errorf("invalid protocol: %q", protocol)
	}
}
