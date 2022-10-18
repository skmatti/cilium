package client

import (
	"github.com/cilium/cilium/pkg/defaults"
	"k8s.io/client-go/rest"
)

func CreateDefaultConfig() (*rest.Config, error) {
	// We don't use the cli to configure APIServerURL and KubeConfigPath,
	// so we should leave them empty to achieve the same behavior before
	// the upstream removed them from the init path
	return createConfig("", "", defaults.K8sClientQPSLimit, defaults.K8sClientBurst)
}
