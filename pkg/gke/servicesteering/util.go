package servicesteering

import (
	v1 "gke-internal.googlesource.com/anthos-networking/apis/v2/service-steering/v1"
	"k8s.io/apimachinery/pkg/api/meta"
)

func CRDsExist(rest meta.RESTMapper) (bool, error) {
	version := v1.GroupVersion.Version
	if _, err := rest.RESTMapping(v1.Kind(v1.KindServiceFunctionChain), version); err != nil {
		return false, ignoreNoMatchError(err)
	}
	if _, err := rest.RESTMapping(v1.Kind(v1.KindTrafficSelector), version); err != nil {
		return false, ignoreNoMatchError(err)
	}
	return true, nil
}

func ignoreNoMatchError(err error) error {
	if meta.IsNoMatchError(err) {
		return nil
	}
	return err
}
