package pip

import (
	"context"
	"fmt"

	networkv1 "github.com/GoogleCloudPlatform/gke-networking-api/apis/network/v1"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/gke/multinic/multinicconfig"
	config "github.com/cilium/cilium/pkg/gke/pip/config"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/promise"
	"github.com/cilium/cilium/pkg/time"
	"github.com/cilium/hive/cell"
	pipv1 "gke-internal.googlesource.com/anthos-networking/apis/v2/persistent-ip/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
)

var (
	piplog = logging.DefaultLogger.WithField(logfields.LogSubsys, "persistentip")
)

var Cell = cell.Module(
	"persistent-ip",
	"Persistent IP",
	config.Cell,
	cell.Invoke(setupPersistentIPCtrl),
)

type persistentIPParams struct {
	cell.In
	Lifecycle      cell.Lifecycle
	Clientset      k8sClient.Clientset
	Config         config.Config
	GoogleMultiNIC multinicconfig.Config
	EmPromise      promise.Promise[endpointmanager.EndpointManager]
}

// TODO(b/301965594) - Migrate controller off of controller runtime
func setupPersistentIPCtrl(params persistentIPParams) error {
	if !params.Config.EnableGooglePersistentIP {
		return nil
	}
	var mgrCtx context.Context
	var cancel context.CancelFunc
	params.Lifecycle.Append(cell.Hook{
		OnStart: func(ctx cell.HookContext) error {
			// create and start a new controller manager for persistent-IP
			scheme := runtime.NewScheme()
			utilruntime.Must(pipv1.AddToScheme(scheme))
			utilruntime.Must(networkv1.AddToScheme(scheme))
			restConfig := params.Clientset.RestConfig()
			mgr, err := ctrl.NewManager(restConfig, ctrl.Options{
				Scheme: scheme,
				Metrics: metricsserver.Options{
					BindAddress: "0",
				},
				NewCache: filteredCache(restConfig, scheme),
			})
			if err != nil {
				return err
			}
			endpointManager, err := params.EmPromise.Await(ctx)
			if err != nil {
				return err
			}
			if err := (&GKEIPRouteReconciler{
				Client:                mgr.GetClient(),
				em:                    endpointManager,
				Log:                   piplog,
				googleMultiNICEnabled: params.GoogleMultiNIC.EnableGoogleMultiNIC,
			}).SetupWithManager(mgr); err != nil {
				return fmt.Errorf("failed to setup persistent ip controller manager: %v", err)
			}
			// creating a new context becase hive context times out
			// after 5 mins.
			mgrCtx, cancel = context.WithCancel(context.Background())
			go start(mgrCtx, mgr)
			return nil
		},
		OnStop: func(hc cell.HookContext) error {
			cancel()
			return nil
		},
	})
	return nil
}

func start(ctx context.Context, mgr ctrl.Manager) {
	if err := mgr.Start(ctx); err != nil {
		piplog.Errorf("error while starting persitent-ip controller: %v", err)
	}
}

// FilteredCache returns a cache with a ListWatch that's restricted to the desired fields in order
// to reduce memory consumption.
func filteredCache(config *rest.Config, scheme *runtime.Scheme) cache.NewCacheFunc {
	resyncInterval := time.Minute * 10
	cacheOptions := cache.Options{
		Scheme:     scheme,
		SyncPeriod: &resyncInterval,
		ByObject: map[client.Object]cache.ByObject{
			&networkv1.Network{}: {},
			&pipv1.GKEIPRoute{}:  {},
		},
	}
	return func(config *rest.Config, opts cache.Options) (cache.Cache, error) {
		return cache.New(config, cacheOptions)
	}
}
