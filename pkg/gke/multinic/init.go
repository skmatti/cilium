package multinic

import (
	"context"
	"errors"
	"fmt"

	"github.com/cilium/cilium/pkg/gke/multinic/controller"
	"github.com/cilium/cilium/pkg/gke/multinic/dhcp"
	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	networkv1alpha1 "gke-internal.googlesource.com/anthos-networking/apis/v2/network/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"

	"github.com/cilium/cilium/pkg/endpointmanager"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
)

var (
	log = logging.DefaultLogger.WithField(logfields.LogSubsys, "multinic")
)

// Init sets up the controller manager and reconcilers for multinic.
func Init(ctx context.Context, endpointManager *endpointmanager.EndpointManager) (K8sClient, *KubeletClient, dhcp.DHCPClient, error) {
	kubeConfig, err := k8s.CreateConfig()
	if err != nil {
		return nil, nil, nil, err
	}
	scheme := runtime.NewScheme()
	// The controller runs on every node. Consider performance impact when adding new schemes.
	if err := networkv1alpha1.AddToScheme(scheme); err != nil {
		return nil, nil, nil, errors.New("failed to add scheme with network APIs")
	}
	if err := corev1.AddToScheme(scheme); err != nil {
		return nil, nil, nil, errors.New("failed to add scheme with core APIs")
	}

	mgr, err := ctrl.NewManager(kubeConfig, ctrl.Options{
		Scheme:             scheme,
		MetricsBindAddress: "0",
	})
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to create manager: %v", err)
	}

	if err = (&controller.NetworkReconciler{
		Client:          mgr.GetClient(),
		EndpointManager: endpointManager,
		NodeName:        nodeTypes.GetName(),
	}).SetupWithManager(mgr); err != nil {
		return nil, nil, nil, fmt.Errorf("failed to setup network controller: %v", err)
	}
	log.Info("Starting multinic controller manager")
	go func() {
		if err := mgr.Start(ctx); err != nil {
			log.WithError(err).Fatal("failed to run multinic controller manager")
		}
		log.Info("Stopped multinic controller manager")
	}()

	kubeletClient, err := NewKubeletClient(ctx)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to create kubelet client: %v", err)
	}

	return NewK8sClient(mgr.GetClient()), kubeletClient, dhcp.NewDHCPClient(), nil
}
