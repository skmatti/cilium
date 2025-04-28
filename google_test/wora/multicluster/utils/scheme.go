package utils

import (
	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/runtime"
	runtimeutil "k8s.io/apimachinery/pkg/util/runtime"
)

func Scheme() *runtime.Scheme {
	scheme := runtime.NewScheme()

	runtimeutil.Must(appsv1.AddToScheme(scheme))
	runtimeutil.Must(corev1.AddToScheme(scheme))
	runtimeutil.Must(metav1.AddToScheme(scheme))
	runtimeutil.Must(rbacv1.AddToScheme(scheme))

	return scheme
}
