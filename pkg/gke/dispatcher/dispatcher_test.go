// +build !privileged_tests

package dispatcher

import (
	"context"
	"sync"
	"testing"

	"github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/pkg/monitor/api"
)

// TestAddFlowListener tests multiple flow listeners can be added.
func TestAddFlowListener(t *testing.T) {
	dpatcher := NewDispatcher()
	observer := dpatcher.(Observer)
	policyCh := make(chan *flow.Flow, 1)
	err := dpatcher.AddFlowListener("policy", api.MessageTypePolicyVerdict, policyCh)
	if err != nil {
		t.Fatalf("AddFlowListener(\"policy\", api.MessageTypePolicyVerdict, %v) = %v, want nil", policyCh, err)
	}

	traceCh := make(chan *flow.Flow, 1)
	err = dpatcher.AddFlowListener("trace", api.MessageTypeTrace, traceCh)
	if err != nil {
		t.Fatalf("AddFlowListener(\"flow\", api.MessageTypetrace, %v) = %v, want nil", traceCh, err)
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		p := <-policyCh
		t.Logf("Policy chan %v receives a flow: %v", policyCh, p)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		p := <-traceCh
		t.Logf("Trace chan %v receives a flow: %v", traceCh, p)
	}()
	observer.OnDecodedFlow(context.TODO(),
		&flow.Flow{EventType: &flow.CiliumEventType{Type: api.MessageTypePolicyVerdict}})

	observer.OnDecodedFlow(context.TODO(),
		&flow.Flow{EventType: &flow.CiliumEventType{Type: api.MessageTypeTrace}})
	wg.Wait()
	t.Logf("Received both events. Finish the test.")
}

func verifyFlowListeners(t *testing.T, d *dispatcher, typ int32, expect int) {
	n := len(d.getFlowListener(typ))
	if n != expect {
		t.Errorf("len(d.getFlowListener(%d)) = %d, want %d",
			typ, n, expect)
	}
}

// TestRemoveFlowListener tests flow listeners can be removed.
func TestRemoveFlowListener(t *testing.T) {
	dpatcher := &dispatcher{
		flowListeners: make(map[int32]map[string]*flowListener),
	}
	policyCh := make(chan *flow.Flow, 1)
	err := dpatcher.AddFlowListener("policy", api.MessageTypePolicyVerdict, policyCh)
	if err != nil {
		t.Fatalf("AddFlowListener(\"policy\", api.MessageTypePolicyVerdict, %v) = %v, want nil", policyCh, err)
	}
	traceCh1 := make(chan *flow.Flow, 1)
	err = dpatcher.AddFlowListener("trace1", api.MessageTypeTrace, traceCh1)
	if err != nil {
		t.Fatalf("AddFlowListener(\"trace1\", api.MessageTypetrace, %v) = %v, want nil", traceCh1, err)
	}
	traceCh2 := make(chan *flow.Flow, 1)
	err = dpatcher.AddFlowListener("trace2", api.MessageTypeTrace, traceCh2)
	if err != nil {
		t.Fatalf("AddFlowListener(\"trace2\", api.MessageTypetrace, %v) = %v, want nil", traceCh2, err)
	}

	verifyFlowListeners(t, dpatcher, api.MessageTypePolicyVerdict, 1)
	verifyFlowListeners(t, dpatcher, api.MessageTypeTrace, 2)

	dpatcher.RemoveFlowListener("policy", api.MessageTypePolicyVerdict)
	verifyFlowListeners(t, dpatcher, api.MessageTypePolicyVerdict, 0)

	dpatcher.RemoveFlowListener("trace1", api.MessageTypeTrace)
	verifyFlowListeners(t, dpatcher, api.MessageTypeTrace, 1)

	dpatcher.RemoveFlowListener("trace2", api.MessageTypeTrace)
	verifyFlowListeners(t, dpatcher, api.MessageTypeTrace, 0)
}
