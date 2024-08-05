package strictegresspolicyvalidation

import (
	"fmt"

	"github.com/cilium/cilium/pkg/datapath/linux/config/defines"
	"github.com/cilium/cilium/pkg/gke/strictegresspolicyvalidation/controller"
	"github.com/cilium/cilium/pkg/maps/egressmap"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/hive/cell"
)

var Cell = cell.Module(
	"strict-egress-policy-validation",
	"Strict Egress Policy Validation",

	cell.Config(defaultConfig),
	cell.Provide(initStrictEgressPolicyValidation),
)

var defaultConfig = controller.Config{
	EnableStrictEgressPolicyValidation:                        controller.DefaultEnableStrictEgressPolicyValidation,
	StrictEgressPolicyValidationAllowAccessLabels:             controller.DefaultStrictEgressPolicyValidationAllowAccessLabels,
	StrictEgressPolicyValidationReconciliationTriggerInterval: controller.DefaultStrictEgressPolicyValidationReconciliationTriggerInterval,
}

func initStrictEgressPolicyValidation(params controller.Params) (out struct {
	cell.Out

	StrictEgressPolicyManager
	defines.NodeOut
}, err error) {
	if !params.Config.EnableStrictEgressPolicyValidation {
		return out, nil
	}
	if !params.DaemonConfig.EnableIPv4EgressGateway {
		return out, fmt.Errorf("strict egress policy requires --%s=\"true\"", option.EnableIPv4EgressGateway)
	}
	if !option.Config.EnableIPv4 {
		return out, fmt.Errorf("strict egress policy requires --%s=\"true\"", option.EnableIPv4Name)
	}

	c, err := controller.NewController(&params)
	if err != nil {
		return out, fmt.Errorf("failed to instantiate strict egress policy controller %v", err)
	}
	out.StrictEgressPolicyManager = c

	out.NodeDefines = map[string]string{
		"ENABLE_GOOGLE_STRICT_EGRESS_POLICY_VALIDATION": "1",
	}
	return out, nil
}

type StrictEgressPolicyManager interface {
	IsStrictEgressPolicy(key *egressmap.EgressPolicyKey4, val *egressmap.EgressPolicyVal4) bool
	IsValidStrictEgressPolicy(key *egressmap.EgressPolicyKey4, val *egressmap.EgressPolicyVal4) bool
	Reconcile()
}

var _ StrictEgressPolicyManager = (*controller.Controller)(nil)
