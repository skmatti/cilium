package scheme

import (
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	runtimeutil "k8s.io/apimachinery/pkg/util/runtime"
	networkv1 "k8s.io/cloud-provider-gcp/crd/apis/network/v1"

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

	return scheme
}
