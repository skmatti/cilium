package nodefirewall

import (
	"fmt"

	"gke-internal/gke-node-firewall/pkg/client/nodenetworkpolicy/clientset/versioned"

	"github.com/cilium/cilium/pkg/gke/nodefirewall/agent"
	"github.com/cilium/cilium/pkg/gke/nodefirewall/logging"
	"github.com/cilium/cilium/pkg/gke/nodefirewall/types"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/promise"
	"github.com/spf13/pflag"
	"k8s.io/client-go/kubernetes"
)

var Cell = cell.Module(
	"node-firewall",
	"Node Firewall",

	cell.Provide(nodeFirewallClient),
	cell.Config(defaultConfig),
	cell.Invoke(registerNodeFirewall),
)

type nodeFirewallManager struct {
	kubeClient         kubernetes.Interface
	nodeFirewallClient *versioned.Clientset
	pmPromise          promise.Promise[types.PolicyManager]
	agent              *agent.NodeFirewallAgent
}

type nodeFirewallParams struct {
	cell.In

	Lifecycle          hive.Lifecycle
	Config             Config
	DaemonConfig       *option.DaemonConfig
	Clientset          k8sClient.Clientset
	NodeFirewallClient *versioned.Clientset
	PmPromise          promise.Promise[types.PolicyManager]
}

type Config struct {
	EnableNodeNetworkPolicyCRD bool
}

var defaultConfig = Config{
	// Default to true to preserve existing enablement behavior.
	EnableNodeNetworkPolicyCRD: true,
}

func (cfg Config) Flags(flags *pflag.FlagSet) {
	flags.Bool(option.EnableNodeNetworkPolicyCRD, defaultConfig.EnableNodeNetworkPolicyCRD, fmt.Sprintf("Enable node network policy CRD. Enforcement requires %q to be enabled.", option.EnableHostFirewall))
	flags.MarkHidden(option.EnableNodeNetworkPolicyCRD)
}

func nodeFirewallClient(clientset k8sClient.Clientset) (*versioned.Clientset, error) {
	nodeFirewallClient, err := versioned.NewForConfig(clientset.RestConfig())
	if err != nil {
		return nil, fmt.Errorf("failed to create NodeNetworkPolicy client: %v", err)
	}
	return nodeFirewallClient, nil
}

func registerNodeFirewall(params nodeFirewallParams) {
	if !(params.DaemonConfig.EnableHostFirewall && params.Config.EnableNodeNetworkPolicyCRD) {
		return
	}

	params.Lifecycle.Append(&nodeFirewallManager{
		kubeClient:         params.Clientset,
		nodeFirewallClient: params.NodeFirewallClient,
		pmPromise:          params.PmPromise,
	})
}

func (m *nodeFirewallManager) Start(ctx hive.HookContext) error {
	policyManager, err := m.pmPromise.Await(ctx)
	if err != nil {
		return fmt.Errorf("failed to get policy manager: %v", err)
	}

	logging.NodeFWLogger.Info("Starting node firewall agent")
	m.agent = agent.NewNodeFirewallAgent(m.kubeClient, m.nodeFirewallClient, policyManager)

	m.agent.Run()
	logging.NodeFWLogger.Info("Node firewall agent started")
	return nil
}

func (m *nodeFirewallManager) Stop(ctx hive.HookContext) error {
	m.agent.Shutdown()
	return nil
}
