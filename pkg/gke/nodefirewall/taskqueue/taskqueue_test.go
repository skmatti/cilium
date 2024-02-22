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

package taskqueue

import (
	"errors"
	"reflect"
	"testing"

	"k8s.io/client-go/tools/cache"
)

func TestPeriodicTaskQueue(t *testing.T) {
	t.Parallel()
	synced := map[string]bool{}
	doneCh := make(chan struct{}, 1)

	var tq TaskQueue
	sync := func(key string) error {
		synced[key] = true
		switch key {
		case "err":
			return errors.New("injected error")
		case "stop":
			doneCh <- struct{}{}
		case "more":
			t.Error("synced after TaskQueue.Shutdown()")
		}
		return nil
	}
	tq = NewPeriodicTaskQueue("test", sync)

	go tq.Run()
	tq.Enqueue(cache.ExplicitKey("a"))
	tq.Enqueue(cache.ExplicitKey("b"))
	tq.Enqueue(cache.ExplicitKey("err"))
	tq.Enqueue(cache.ExplicitKey("stop"))

	<-doneCh
	tq.Shutdown()

	// Enqueue after Shutdown isn't going to be synced.
	tq.Enqueue(cache.ExplicitKey("more"))

	expected := map[string]bool{
		"a":    true,
		"b":    true,
		"err":  true,
		"stop": true,
	}

	if !reflect.DeepEqual(synced, expected) {
		t.Errorf("task queue synced %+v, want %+v", synced, expected)
	}
}
