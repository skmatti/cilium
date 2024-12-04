package convert

import (
	"fmt"

	"github.com/cilium/cilium/pkg/gke/apis/fqdnnetworkpolicy/v1alpha1"
	"k8s.io/client-go/tools/cache"
)

const (
	ResourceTypeFQDNNetworkPolicy = "FQDNNetworkPolicy"
)

// ObjToFQDNNetworkPolicy converts a provided object into a FQDN Network Policy object.
func ObjToFQDNNetworkPolicy(obj interface{}) (*v1alpha1.FQDNNetworkPolicy, error) {
	fqdn, ok := obj.(*v1alpha1.FQDNNetworkPolicy)
	if ok {
		return fqdn, nil
	}
	dfsu, ok := obj.(*cache.DeletedFinalStateUnknown)
	if !ok {
		return nil, fmt.Errorf("invalid object type %T", obj)
	}
	fqdn, ok = dfsu.Obj.(*v1alpha1.FQDNNetworkPolicy)
	if !ok {
		return nil, fmt.Errorf("invalid object type in DeletedFinalStateUnknown %T", obj)
	}
	return fqdn, nil
}
