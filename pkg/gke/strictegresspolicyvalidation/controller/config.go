package controller

import (
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/time"
	"github.com/spf13/pflag"
)

type Config struct {
	// EnableStrictEgressPolicyValidation enables checks on traffic egressing from infra cluster.
	EnableStrictEgressPolicyValidation bool
	// StrictEgressPolicyValidationAllowAccessLabels sets the pod label selectors for egress routing policy,
	// which will be used to determine if a pod has egress routing access.
	StrictEgressPolicyValidationAllowAccessLabels             []string      `mapstructure:"strict-egress-policy-validation-allow-access-labels"`
	StrictEgressPolicyValidationReconciliationTriggerInterval time.Duration `mapstructure:"strict-egress-policy-validation-reconciliation-trigger-interval"`
}

func (def Config) Flags(flags *pflag.FlagSet) {
	flags.Bool(option.EnableStrictEgressPolicyValidation,
		def.EnableStrictEgressPolicyValidation,
		"Enable Google strict egress policy functionality.")
	flags.MarkHidden(option.EnableStrictEgressPolicyValidation)

	flags.StringSlice(option.StrictEgressPolicyValidationAllowAccessLabels,
		def.StrictEgressPolicyValidationAllowAccessLabels,
		"Label selectors to determine if a pod has Google strict egress policy access. The label selectors will be ORed.")
	flags.MarkHidden(option.StrictEgressPolicyValidationAllowAccessLabels)

	flags.Duration(option.StrictEgressPolicyValidationReconciliationTriggerInterval,
		def.StrictEgressPolicyValidationReconciliationTriggerInterval,
		"Time between triggers of Google strict egress policy state reconciliations")
	flags.MarkHidden(option.StrictEgressPolicyValidationReconciliationTriggerInterval)
}
