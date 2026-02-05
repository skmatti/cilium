package networking

import (
	"fmt"
	gkenetworkv1client "github.com/GoogleCloudPlatform/gke-networking-api/client/network/clientset/versioned"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/hive/cell"
)

var Cell = cell.Module(
	"gke-networking",
	"GKE Networking Client",
	cell.Provide(newNetworkClient),
)

func newNetworkClient(clientset k8sClient.Clientset) (gkenetworkv1client.Interface, error) {
	if !clientset.IsEnabled() {
		return nil, nil // Or return an error if this client is strictly required
	}
	restConfig := clientset.RestConfig()
	gkenwClient, err := gkenetworkv1client.NewForConfig(restConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create GKE network client: %w", err)
	}
	return gkenwClient, nil
}
