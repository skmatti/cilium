package watchers

import (
	"context"
	"sync"

	"github.com/cilium/cilium/pkg/k8s"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/informer"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/k8s/utils"
	"k8s.io/client-go/tools/cache"
)

type nsUpdateHandlerFunc func(newNS, oldNS *slim_corev1.Namespace)

var (
	NSStore cache.Store

	nsOnUpdateHandlers []nsUpdateHandlerFunc
)

func NamespaceWatcherInit(ctx context.Context, wg *sync.WaitGroup, clientset k8sClient.Clientset) {
	log.Info("Initializing Namespace informer")

	namespaceStore, namespaceInformer := informer.NewInformer(
		utils.ListerWatcherFromTyped[*slim_corev1.NamespaceList](clientset.Slim().CoreV1().Namespaces()),
		&slim_corev1.Namespace{},
		0,
		cache.ResourceEventHandlerFuncs{
			// AddFunc does not matter since the endpoint will fetch
			// namespace labels when the endpoint is created
			// DelFunc does not matter since, when a namespace is deleted, all
			// pods belonging to that namespace are also deleted.
			UpdateFunc: func(oldObj, newObj interface{}) {
				if oldNS := k8s.ObjToV1Namespace(oldObj); oldNS != nil {
					if newNS := k8s.ObjToV1Namespace(newObj); newNS != nil {
						if oldNS.DeepEqual(newNS) {
							return
						}

						processNSUpdate(newNS, oldNS)
					}
				}
			},
		},
		nil,
	)

	NSStore = namespaceStore

	wg.Add(1)
	go func() {
		defer wg.Done()
		namespaceInformer.Run(ctx.Done())
	}()

	cache.WaitForCacheSync(ctx.Done(), namespaceInformer.HasSynced)
}

func processNSUpdate(newNS, oldNS *slim_corev1.Namespace) {
	for _, f := range nsOnUpdateHandlers {
		f(newNS, oldNS)
	}
}

func SubscribeToNSUpdateEvents(f func(newNS *slim_corev1.Namespace, oldNS *slim_corev1.Namespace)) {
	nsOnUpdateHandlers = append(nsOnUpdateHandlers, f)
}
