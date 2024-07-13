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
	"fmt"

	"github.com/cilium/cilium/pkg/gke/features"
	servicesteeringconfig "github.com/cilium/cilium/pkg/gke/servicesteering/config"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/hive/cell"
)

// NOTE: The Cell name is deliberately obscured to "gke-multi-project" to
// avoid directly revealing the GKE Multi-tenancy feature to all customers
// during startup logs, even those not using it. This decision was made in
// consultation with the wider GKE Multi-tenancy team.
var Cell = cell.Module(
	"gke-multi-project",
	"GKE Multi Project",

	cell.Invoke(validateMultiTenancyDependentParams),
)

func validateMultiTenancyDependentParams(params multiTenancyParams) error {
	if !params.GKEFeaturesConfig.EnableGKEMultiTenancy {
		// Nothing to validate if multi-tenancy is not enabled.
		return nil
	}

	// CiliumNode is a cluster-scoped resource, so we disable it's automatic
	// creation.
	if params.DaemonConfig.AutoCreateCiliumNodeResource {
		return fmt.Errorf("%v cannot be enabled when %v=%v", option.AutoCreateCiliumNodeResource, option.EnableGKEMultiTenancy, "true")
	}

	// ServiceSteering is being disabled since it requires some cluster-scoped
	// resources (ServiceFunctionChain, TrafficSelector)
	if params.ServiceSteeringConfig.EnableGoogleServiceSteering {
		return fmt.Errorf("%v cannot be enabled when %s=%s", servicesteeringconfig.EnableFlag, option.EnableGKEMultiTenancy, "true")
	}

	return nil
}

type multiTenancyParams struct {
	cell.In

	DaemonConfig          *option.DaemonConfig
	GKEFeaturesConfig     features.Config
	ServiceSteeringConfig servicesteeringconfig.Config `optional:"true"`
}
