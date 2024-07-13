/*
Copyright 2024 Google LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package multitenancy

import (
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
)

const (
	TenantAccessControlLabel                = "tenancy.gke.io/access-control"
	TenantAccessControlAllTenantsVisibility = "all-tenants"
)

// SupportedCRDs returns a list of CRDs supported in GKE Multi-tenancy mode.
func SupportedCRDs() []string {
	return []string{
		v2.CIDName,
		v2.CEPName,
		v2.CNName,
		v2alpha1.CESName,
		v2.CLRPName,
	}
}
