package watchers

import (
	"fmt"
	"strconv"

	"github.com/cilium/cilium/pkg/allocator"
	"github.com/cilium/cilium/pkg/identity/key"
	"github.com/cilium/cilium/pkg/idpool"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/typed/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/informer"
	metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/kvstore"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/client-go/tools/cache"
)

const (
	// byKeyIndex is the name of the index of the identities by key.
	ByKeyIndex = "by-key-index"
)

var (
	CIDStore            cache.Indexer
	CIDInformerIsSynced bool

	cidEventAddSubscribers    []func(cid *v2.CiliumIdentity)
	cidEventUpdateSubscribers []func(cid *v2.CiliumIdentity)
	cidEventDeleteSubscribers []func(cid *v2.CiliumIdentity)
)

func InitCIDWatcher(ciliumNPClient ciliumv2.CiliumV2Interface, stopChan chan struct{}) {
	log.Info("Initializing Cilium Identity informer")

	keyFunc := (&key.GlobalIdentity{}).PutKeyFromMap

	CIDStore = cache.NewIndexer(
		cache.DeletionHandlingMetaNamespaceKeyFunc,
		cache.Indexers{ByKeyIndex: GetIdentitiesByKeyFunc(keyFunc)})
	identityInformer := informer.NewInformerWithStore(
		cache.NewListWatchFromClient(ciliumNPClient.RESTClient(),
			v2.CIDPluralName, metav1.NamespaceAll, fields.Everything()),
		&v2.CiliumIdentity{},
		0,
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				if identity, ok := obj.(*v2.CiliumIdentity); ok {
					if _, err := strconv.ParseUint(identity.Name, 10, 64); err == nil {
						processCIDAddEvent(identity)
					}
				}
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				if oldIdentity, ok := newObj.(*v2.CiliumIdentity); ok {
					if newIdentity, ok := newObj.(*v2.CiliumIdentity); ok {
						if oldIdentity.DeepEqual(newIdentity) {
							return
						}
						if _, err := strconv.ParseUint(newIdentity.Name, 10, 64); err == nil {
							processCIDUpdateEvent(newIdentity)
						}
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
					if _, err := strconv.ParseUint(identity.Name, 10, 64); err == nil {
						processCIDDeleteEvent(identity)
					}
				} else {
					log.Debugf("Ignoring unknown delete event %#v", obj)
				}
			},
		},
		nil,
		CIDStore,
	)

	go identityInformer.Run(stopChan)

	if !cache.WaitForCacheSync(stopChan, identityInformer.HasSynced) {
		log.Fatalf("Failed to sync identity informer")
		return
	}

	CIDInformerIsSynced = true
	log.Info("Cilium Identity informer is synced")
}

func GetIdentitiesByKeyFunc(keyFunc func(map[string]string) allocator.AllocatorKey) func(obj interface{}) ([]string, error) {
	return func(obj interface{}) ([]string, error) {
		if identity, ok := obj.(*v2.CiliumIdentity); ok {
			return []string{keyFunc(identity.SecurityLabels).GetKey()}, nil
		}
		return []string{}, fmt.Errorf("object other than CiliumIdentity was pushed to the store")
	}
}

func sendEvent(eventsChan allocator.AllocatorEventChan, typ kvstore.EventType, id idpool.ID, key allocator.AllocatorKey) {
	if events := eventsChan; events != nil {
		events <- allocator.AllocatorEvent{Typ: typ, ID: id, Key: key}
	}
}

func processCIDAddEvent(cid *v2.CiliumIdentity) {
	for _, f := range cidEventAddSubscribers {
		f(cid)
	}
}

func processCIDUpdateEvent(cid *v2.CiliumIdentity) {
	for _, f := range cidEventUpdateSubscribers {
		f(cid)
	}
}

func processCIDDeleteEvent(cid *v2.CiliumIdentity) {
	for _, f := range cidEventDeleteSubscribers {
		f(cid)
	}
}

func AddCIDEventAddSubscriber(f func(cid *v2.CiliumIdentity)) {
	cidEventAddSubscribers = append(cidEventAddSubscribers, f)
}

func AddCIDEventUpdateSubscriber(f func(cid *v2.CiliumIdentity)) {
	cidEventUpdateSubscribers = append(cidEventUpdateSubscribers, f)
}

func AddCIDEventDeleteSubscriber(f func(cid *v2.CiliumIdentity)) {
	cidEventDeleteSubscribers = append(cidEventDeleteSubscribers, f)
}
