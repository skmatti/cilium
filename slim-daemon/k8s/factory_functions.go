package k8s

import (
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"k8s.io/client-go/tools/cache"
)

func ObjTov1Pod(obj interface{}) *slim_corev1.Pod {
	pod, ok := obj.(*slim_corev1.Pod)
	if ok {
		return pod
	}
	deletedObj, ok := obj.(cache.DeletedFinalStateUnknown)
	if ok {
		// Delete was not observed by the watcher but is
		// removed from kube-apiserver. This is the last
		// known state and the object no longer exists.
		pod, ok := deletedObj.Obj.(*slim_corev1.Pod)
		if ok {
			return pod
		}
	}
	log.WithField(logfields.Object, logfields.Repr(obj)).
		Warn("Ignoring invalid k8s v1 Pod")
	return nil
}
