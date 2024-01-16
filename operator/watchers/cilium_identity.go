package watchers

import (
	"context"
	"fmt"
	"sync"

	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/client-go/tools/cache"

	"github.com/cilium/cilium/pkg/allocator"
	"github.com/cilium/cilium/pkg/identity/key"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/informer"
)

type EventType int

type cidHandlerFunc func(cid *v2.CiliumIdentity)

const (
	ByKeyIndex = "by-key-index"
)

const (
	AddEvent EventType = iota
	UpdateEvent
	DeleteEvent
)

func (e EventType) String() string {
	var eventStr string

	switch e {
	case AddEvent:
		eventStr = "AddEvent"
	case UpdateEvent:
		eventStr = "UpdateEvent"
	case DeleteEvent:
		eventStr = "DeleteEvent"
	default:
		eventStr = "UNKNOWN"
	}

	return eventStr
}

var (
	CIDStore cache.Indexer

	IdentityKeyFunc = (&key.GlobalIdentity{}).PutKeyFromMap

	cidOnAddHandlers    []cidHandlerFunc
	cidOnUpdateHandlers []cidHandlerFunc
	cidOnDeleteHandlers []cidHandlerFunc
)

func GetIdentitiesByKeyFunc(keyFunc func(map[string]string) allocator.AllocatorKey) func(obj interface{}) ([]string, error) {
	return func(obj interface{}) ([]string, error) {
		if identity, ok := obj.(*v2.CiliumIdentity); ok {
			return []string{keyFunc(identity.SecurityLabels).GetKey()}, nil
		}
		return []string{}, fmt.Errorf("object other than CiliumIdentity was pushed to the store")
	}
}

func CiliumIdentityWatcherInit(ctx context.Context, wg *sync.WaitGroup, clientset k8sClient.Clientset) {
	log.Info("Initializing Cilium Identity informer")

	k8sCiliumClient := clientset.CiliumV2()

	identityStore := cache.NewIndexer(
		cache.DeletionHandlingMetaNamespaceKeyFunc,
		cache.Indexers{ByKeyIndex: GetIdentitiesByKeyFunc(IdentityKeyFunc)})

	identityInformer := informer.NewInformerWithStore(
		cache.NewListWatchFromClient(k8sCiliumClient.RESTClient(),
			v2.CIDPluralName, v1.NamespaceAll, fields.Everything()),
		&v2.CiliumIdentity{},
		0,
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				if identity, ok := obj.(*v2.CiliumIdentity); ok {
					processCIDAdd(identity)
				}
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				if oldIdty, ok := oldObj.(*v2.CiliumIdentity); ok {
					if newIdty, ok := newObj.(*v2.CiliumIdentity); ok {
						if oldIdty.DeepEqual(newIdty) {
							return
						}
						processCIDUpdate(newIdty)
					}
				}
			},
			DeleteFunc: func(obj interface{}) {
				// The delete event is sometimes for items with unknown state that are
				// deleted anyway.
				if deleteObj, isDeleteObj := obj.(cache.DeletedFinalStateUnknown); isDeleteObj {
					obj = deleteObj.Obj
				}

				if identity, ok := obj.(*v2.CiliumIdentity); ok {
					processCIDDelete(identity)
				} else {
					log.Infof("CID watcher ignoring unknown delete event %#v", obj)
				}
			},
		},
		nil,
		identityStore,
	)

	CIDStore = identityStore

	wg.Add(1)
	go func() {
		defer wg.Done()
		identityInformer.Run(ctx.Done())
	}()

	cache.WaitForCacheSync(ctx.Done(), identityInformer.HasSynced)
}

func processCIDAdd(cid *v2.CiliumIdentity) {
	for _, f := range cidOnAddHandlers {
		f(cid)
	}
}

func processCIDUpdate(cid *v2.CiliumIdentity) {
	for _, f := range cidOnUpdateHandlers {
		f(cid)
	}
}

func processCIDDelete(cid *v2.CiliumIdentity) {
	for _, f := range cidOnDeleteHandlers {
		f(cid)
	}
}

func SubscribeToCIDAddEvents(f func(cid *v2.CiliumIdentity)) {
	cidOnAddHandlers = append(cidOnAddHandlers, f)
}

func SubscribeToCIDUpdateEvents(f func(cid *v2.CiliumIdentity)) {
	cidOnUpdateHandlers = append(cidOnUpdateHandlers, f)
}

func SubscribeToCIDDeleteEvents(f func(cid *v2.CiliumIdentity)) {
	cidOnDeleteHandlers = append(cidOnDeleteHandlers, f)
}
