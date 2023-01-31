package servicesteering

import (
	"context"

	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v1 "gke-internal.googlesource.com/anthos-networking/apis/v2/service-steering/v1"
)

var (
	sfclog = logging.DefaultLogger.WithField(logfields.LogSubsys, "gke-sfc-controller")
)

type ServiceFunctionChainReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

func (r *ServiceFunctionChainReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&v1.ServiceFunctionChain{}).
		Complete(r)
}

func (r *ServiceFunctionChainReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := sfclog.WithField("name", req.Name)
	log.Info("Reconciling")

	var chain v1.ServiceFunctionChain
	if err := r.Get(ctx, req.NamespacedName, &chain); err != nil {
		log.Debug("Unable to fetch SFC")
		// We'll ignore not-found errors, since they can't be fixed by an immediate
		// requeue (we'll need to wait for a new notification), and we can get them
		// on deleted requests.
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	return ctrl.Result{}, nil
}
