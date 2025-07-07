// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package apis

import (
	"fmt"

	"github.com/cilium/hive/cell"
	"github.com/sirupsen/logrus"
	"github.com/spf13/pflag"

	"github.com/cilium/cilium/pkg/gke/features"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/client"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
)

// SkipCRDCreation specifies whether the CustomResourceDefinition will be
// created by the daemon
const SkipCRDCreation = "skip-crd-creation"

// RegisterCRDsCell is a cell that creates all the Cilium CRDs.
var RegisterCRDsCell = cell.Module(
	"create-crds",
	"Create Cilium CRDs",

	cell.Config(defaultConfig),

	cell.Invoke(createCRDs),

	cell.ProvidePrivate(
		newCiliumGroupCRDs,
	),
)

type RegisterCRDsConfig struct {
	// SkipCRDCreation disables creation of the CustomResourceDefinition
	// for the operator
	SkipCRDCreation bool
}

var defaultConfig = RegisterCRDsConfig{}

func (c RegisterCRDsConfig) Flags(flags *pflag.FlagSet) {
	flags.Bool(SkipCRDCreation, false, "When true, Kubernetes Custom Resource Definitions will not be created")
}

// RegisterCRDsFunc is a function that register all the CRDs for a k8s group
type RegisterCRDsFunc func(k8sClient.Clientset) error

type params struct {
	cell.In

	Logger    logrus.FieldLogger
	Lifecycle cell.Lifecycle

	Clientset k8sClient.Clientset

	Config            RegisterCRDsConfig
	RegisterCRDsFuncs []RegisterCRDsFunc `group:"register-crd-funcs"`

	// CRD registration depends on GKE features config
	GKEFeatures features.Config
}

func createCRDs(p params) {
	p.Lifecycle.Append(cell.Hook{
		OnStart: func(ctx cell.HookContext) error {
			// The global config is used by CRD registration functions, so we must
			// update it with the config injected by hive. This is especially
			// important for the operator which may not run the GKE features cell
			// that would otherwise populate this global.
			features.GlobalConfig = p.GKEFeatures
			// Register the CRDs after validating that we are running on a supported
			// version of K8s.
			if !p.Clientset.IsEnabled() || p.Config.SkipCRDCreation {
				p.Logger.Info("Skipping creation of CRDs")
				return nil
			}

			for _, f := range p.RegisterCRDsFuncs {
				if err := f(p.Clientset); err != nil {
					return fmt.Errorf("unable to create CRDs: %w", err)
				}
			}

			return nil
		},
	})
}

type registerCRDsFuncOut struct {
	cell.Out

	Func RegisterCRDsFunc `group:"register-crd-funcs"`
}

func newCiliumGroupCRDs() registerCRDsFuncOut {
	return registerCRDsFuncOut{
		Func: client.RegisterCRDs,
	}
}
