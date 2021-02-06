package subnet

import (
	"context"
	"fmt"
	"net"

	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/promise"
	"github.com/spf13/pflag"
)

var Cell = cell.Module(
	"annotate-subnet",
	"Annotate Subnet",

	cell.Config(defaultConfig),
	cell.Invoke(registerNodeAnnotator),
)

type LocalNodeInfo struct {
	Name string
	IPv4 net.IP
	IPv6 net.IP
}

type Config struct {
	AnnotateK8sNodeSubnet bool
}

var defaultConfig = Config{
	AnnotateK8sNodeSubnet: false,
}

func (cfg Config) Flags(flags *pflag.FlagSet) {
	flags.Bool(option.AnnotateK8sNodeSubnet, defaultConfig.AnnotateK8sNodeSubnet, "Enables annotation of kubernetes nodes with subnet information.")
	flags.MarkHidden(option.AnnotateK8sNodeSubnet)
}

// Annotate the K8s node with subnet information. This will be a no-op if
// the proper config setting is not enabled. These annotations are used by
// Anthos Network Gateway (http://go/ang-design).
func registerNodeAnnotator(lc hive.Lifecycle, config Config, client k8sClient.Clientset, nodePromise promise.Promise[LocalNodeInfo]) {
	if !config.AnnotateK8sNodeSubnet {
		return
	}

	lc.Append(hive.Hook{
		OnStart: func(ctx hive.HookContext) error {
			node, err := nodePromise.Await(ctx)
			if err != nil {
				return fmt.Errorf("failed to get local node: %v", err)
			}

			if node.IPv4 == nil && node.IPv6 == nil {
				log.Error(fmt.Errorf("both IPv4 and IPv6 are nil"), "Could not annotate K8s node subnets.")
				return nil
			}

			controller.NewManager().UpdateController("annotate-k8s-node-subnets",
				controller.ControllerParams{
					// We will not worry about running this repeatedly because if the
					// IPs change, K8s would need to be restarted anyway.
					DoFunc: func(ctx context.Context) error {
						return annotateNodeSubnets(ctx, client, node.Name, node.IPv4, node.IPv6)
					},
				})
			return nil
		},
	})
}
