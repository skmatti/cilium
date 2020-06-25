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

// This is the package for dispatcher that observe the events and dispatch
// it to registered listeners.
package dispatcher

import (
	"context"
	"fmt"

	"github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/monitor/api"
	"github.com/sirupsen/logrus"
)

var (
	log = logging.DefaultLogger.WithField(logfields.LogSubsys, "gke-dispatcher")
)

type flowListener struct {
	name string
	ch   chan *flow.Flow
}

type dispatcher struct {
	mutex lock.Mutex
	// flowListeners is a map from the event type to the map of listeners (name -> flowListener)
	// so that it can be quickly fetched on processing the flow events.
	flowListeners map[int32]map[string]*flowListener
}

// Dispatcher provides the interface for a client to listen to a given type of flow.
// The supported message type is defined in pkg/monitor/api/types.go
type Dispatcher interface {
	AddFlowListener(name string, typ int32, ch chan *flow.Flow) error
	RemoveFlowListener(name string, typ int32)
}

// Observer provides the interface to hook with hubble to observe flows.
type Observer interface {
	OnDecodedFlow(ctx context.Context, pb *flow.Flow) (bool, error)
}

// NewDispatcher returns a new dispatcher that implements both Dispatcher
// and Observer interface.
func NewDispatcher() Dispatcher {
	return &dispatcher{
		flowListeners: make(map[int32]map[string]*flowListener),
	}
}

// AddFlowListener register a listenser to flow type typ. The given flow will be
// sent to the provided channel.
func (d *dispatcher) AddFlowListener(name string, typ int32, ch chan *flow.Flow) error {
	log.WithFields(logrus.Fields{"name": name, "event": api.MessageTypeName(int(typ))}).Info("Add flow listener")
	d.mutex.Lock()
	defer d.mutex.Unlock()
	if ls, ok := d.flowListeners[typ]; !ok {
		ls = map[string]*flowListener{name: {name: name, ch: ch}}
		d.flowListeners[typ] = ls
	} else {
		if _, ok := ls[name]; ok {
			return fmt.Errorf("listener %q exists for type: %q", name, api.MessageTypeName(int(typ)))
		}
		ls[name] = &flowListener{name: name, ch: ch}
	}
	return nil
}

// RemoveFlowListener removes a registered flow listenser for type typ.
func (d *dispatcher) RemoveFlowListener(name string, typ int32) {
	log.WithFields(logrus.Fields{"name": name, "event": api.MessageTypeName(int(typ))}).Info("Remove flow listener")
	d.mutex.Lock()
	defer d.mutex.Unlock()
	ls := d.flowListeners[typ]
	if ls == nil {
		return
	}
	if _, ok := ls[name]; ok {
		delete(ls, name)
	} else {
		log.WithFields(logrus.Fields{"name": name, "event": api.MessageTypeName(int(typ))}).Info("Flow listener doesn't exist")
	}
	if len(ls) == 0 {
		delete(d.flowListeners, typ)
	}
}

// getFlowListener gets the flow listeners for the given type.
func (d *dispatcher) getFlowListener(typ int32) []*flowListener {
	d.mutex.Lock()
	defer d.mutex.Unlock()
	ls, ok := d.flowListeners[typ]
	if !ok {
		return nil
	}
	var ret []*flowListener
	for _, l := range ls {
		ret = append(ret, l)
	}
	return ret
}

// OnDecodedFlow implements the handler after getting the flow from Hubble.
// The return bool decides if the processing of the flow will stop in hubble processing chain.
// Return value of "true" will stop further processing of the flow in the hubble execution chain.
func (d *dispatcher) OnDecodedFlow(ctx context.Context, pb *flow.Flow) (bool, error) {
	typ := pb.GetEventType().GetType()
	ls := d.getFlowListener(typ)
	if ls == nil {
		return false, nil
	}
	for _, l := range ls {
		select {
		case l.ch <- pb:
		default:
			log.WithFields(logrus.Fields{"listener": l.name, "event": api.MessageTypeName(int(typ))}).Info("Queue full. Dropping.")
		}
	}
	return false, nil
}
