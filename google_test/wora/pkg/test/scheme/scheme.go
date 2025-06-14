package scheme

import (
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	"k8s.io/apimachinery/pkg/runtime"
	runtimeutil "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	networkv1 "k8s.io/cloud-provider-gcp/crd/apis/network/v1"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	l4gatewayv1 "gke-internal.googlesource.com/anthos-networking/apis/v2/l4-gateway/v1"
	ipamv1 "gke-internal.googlesource.com/anthos-networking/ipam-controller/api/v1alpha1"
)

func Scheme() *runtime.Scheme {
	scheme := runtime.NewScheme()

	runtimeutil.Must(appsv1.AddToScheme(scheme))
	runtimeutil.Must(corev1.AddToScheme(scheme))
	runtimeutil.Must(batchv1.AddToScheme(scheme))
	runtimeutil.Must(networkv1.AddToScheme(scheme))
	runtimeutil.Must(ciliumv2.AddToScheme(scheme))
	runtimeutil.Must(ipamv1.AddToScheme(scheme))
	runtimeutil.Must(corev1.AddToScheme(scheme))
	runtimeutil.Must(ipamv1.AddToScheme(scheme))
	runtimeutil.Must(clientgoscheme.AddToScheme(scheme))
	runtimeutil.Must(gatewayv1.AddToScheme(scheme))
	runtimeutil.Must(l4gatewayv1.AddToScheme(scheme))
	runtimeutil.Must(discoveryv1.AddToScheme(scheme))

	return scheme
}
