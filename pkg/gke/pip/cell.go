package pip

import (
	"context"
	"fmt"
	"time"

	"github.com/cilium/cilium/pkg/endpointmanager"
	config "github.com/cilium/cilium/pkg/gke/pip/config"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/promise"
	pipv1 "gke-internal.googlesource.com/anthos-networking/apis/v2/persistent-ip/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	networkv1 "k8s.io/cloud-provider-gcp/crd/apis/network/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
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
	Lifecycle hive.Lifecycle
	Clientset k8sClient.Clientset
	Config    config.Config

	EmPromise promise.Promise[*endpointmanager.EndpointManager]
}

// TODO(b/301965594) - Migrate controller off of controller runtime
func setupPersistentIPCtrl(params persistentIPParams) error {
	// TODO(b/292558915) - Remove multiNIC check when persistent IP is supported on default network.
	if !(params.Config.EnableGooglePersistentIP && option.Config.EnableGoogleMultiNIC) {
		return nil
	}
	var mgrCtx context.Context
	var cancel context.CancelFunc
	params.Lifecycle.Append(hive.Hook{
		OnStart: func(ctx hive.HookContext) error {
			// wait until endpointManager is ready
			endpointManager, err := params.EmPromise.Await(ctx)
			if err != nil {
				return fmt.Errorf("failed to get endpoint manager: %v", err)
			}
			// create and start a new controller manager for persistent-IP
			scheme := runtime.NewScheme()
			utilruntime.Must(pipv1.AddToScheme(scheme))
			utilruntime.Must(networkv1.AddToScheme(scheme))
			mgr, err := ctrl.NewManager(params.Clientset.RestConfig(), ctrl.Options{
				Scheme:             scheme,
				MetricsBindAddress: "0",
				NewCache:           filteredCache(),
			})
			if err != nil {
				return err
			}
			if err := (&GKEIPRouteReconciler{
				Client:          mgr.GetClient(),
				EndpointManager: endpointManager,
				Log:             piplog,
			}).SetupWithManager(mgr); err != nil {
				return fmt.Errorf("failed to setup persistent ip controller manager: %v", err)
			}
			// creating a new context becase hive context times out
			// after 5 mins.
			mgrCtx, cancel = context.WithCancel(context.Background())
			go start(mgrCtx, mgr)
			return nil
		},
		OnStop: func(hc hive.HookContext) error {
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
func filteredCache() cache.NewCacheFunc {
	resyncInterval := time.Minute * 10
	return cache.BuilderWithOptions(cache.Options{
		Resync: &resyncInterval,
		SelectorsByObject: cache.SelectorsByObject{
			&networkv1.Network{}: {},
			&pipv1.GKEIPRoute{}:  {},
		},
	})
}
