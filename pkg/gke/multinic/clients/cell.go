package clients

import (
	"context"
	"fmt"
	"net"

	networkv1 "github.com/GoogleCloudPlatform/gke-networking-api/apis/network/v1"
	nwversioned "github.com/GoogleCloudPlatform/gke-networking-api/client/network/clientset/versioned"
	nwFake "github.com/GoogleCloudPlatform/gke-networking-api/client/network/clientset/versioned/fake"
	"github.com/cilium/cilium/pkg/gke/multinic/dhcp"
	"github.com/cilium/cilium/pkg/gke/multinic/multinicconfig"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/k8s/utils"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/hive/cell"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

var (
	log = logging.DefaultLogger.WithField(logfields.LogSubsys, "multinicclients")
)

var Cell = cell.Module(
	"google-multinetworking-clients",
	"Google Multinetworking Clients",
	cell.Provide(networkAPIClient),
	cell.Provide(networkResources),
	cell.Provide(gkeNetworkParamSetResources),
	cell.Provide(networkInterfaceResources),
	cell.Provide(kubeletClient),
	cell.Provide(multiNetworkHelperClient),
	cell.Provide(dhcpClient),
)

type Params struct {
	cell.In

	// Clients required by multinetwork reconciler
	Clientset           k8sClient.Clientset
	NetworkAPIClient    nwversioned.Interface
	Networks            resource.Resource[*networkv1.Network]
	GKENetworkParamSets resource.Resource[*networkv1.GKENetworkParamSet]
	NetworkInterfaces   resource.Resource[*networkv1.NetworkInterface]
	Lifecycle           cell.Lifecycle
	Config              multinicconfig.Config
}

func multiNetworkHelperClient(p Params) (MultiNetworkHelperClient, error) {
	if !p.Config.EnableGoogleMultiNIC {
		return nil, nil
	}
	_, cancel := context.WithCancel(context.Background())
	client := &MultiNetworkHelperClientImpl{
		Clientset:           p.Clientset,
		NWClient:            p.NetworkAPIClient,
		Networks:            p.Networks,
		GKENetworkParamSets: p.GKENetworkParamSets,
		NetworkInterfaces:   p.NetworkInterfaces,
	}
	p.Lifecycle.Append(cell.Hook{
		OnStart: func(ctx cell.HookContext) error {
			return nil
		},
		OnStop: func(hc cell.HookContext) error {
			cancel()
			return nil
		},
	})
	return client, nil
}

func networkAPIClient(clientset k8sClient.Clientset) (nwversioned.Interface, error) {
	if !clientset.IsEnabled() {
		return nil, nil
	}
	nwClient, err := nwversioned.NewForConfig(clientset.RestConfig())
	if err != nil {
		return nil, fmt.Errorf("create network client: %v", err)
	}
	return nwClient, nil
}

// networkResources creates a new resource for network objects.
// Network objects are custom resources defined by the Multinetworking API.
func networkResources(lc cell.Lifecycle, conf multinicconfig.Config, c nwversioned.Interface) (resource.Resource[*networkv1.Network], error) {
	if !conf.EnableGoogleMultiNIC {
		return nil, nil
	}
	return resource.New[*networkv1.Network](
		lc, utils.ListerWatcherFromTyped[*networkv1.NetworkList](c.NetworkingV1().Networks()), resource.WithMetric("Networks")), nil
}

// networkInterfaceResources creates a new resource for network interface objects.
// Network interface objects are custom resources defined by the Multinetworking API.
func networkInterfaceResources(lc cell.Lifecycle, conf multinicconfig.Config, c nwversioned.Interface) (resource.Resource[*networkv1.NetworkInterface], error) {
	if !conf.EnableGoogleMultiNIC {
		return nil, nil
	}
	return resource.New[*networkv1.NetworkInterface](
		lc, utils.ListerWatcherFromTyped[*networkv1.NetworkInterfaceList](c.NetworkingV1().NetworkInterfaces("")), resource.WithMetric("NetworkInterfaces")), nil
}

// gkeNetworkParamSetResources creates a new resource for GKENetworkParamSet objects.
// GKENetworkParamSet objects are custom resources defined by the multinetworking feature and required in GKE.
func gkeNetworkParamSetResources(lc cell.Lifecycle, conf multinicconfig.Config, clientset k8sClient.Clientset, c nwversioned.Interface) (resource.Resource[*networkv1.GKENetworkParamSet], error) {
	if !conf.EnableGoogleMultiNIC {
		return nil, nil
	}
	if !conf.PopulateGCENICInfo {
		return nil, nil
	}
	return resource.New[*networkv1.GKENetworkParamSet](
		lc, utils.ListerWatcherFromTyped[*networkv1.GKENetworkParamSetList](c.NetworkingV1().GKENetworkParamSets()), resource.WithMetric("GKENetworkParamSets")), nil
}

func kubeletClient(p Params) (*KubeletClient, error) {
	if !p.Config.EnableGoogleMultiNIC {
		return nil, nil
	}
	var client *KubeletClient
	var err error
	ctx, cancel := context.WithCancel(context.Background())
	client, err = NewKubeletClient(ctx)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to create kubelet client: %v", err)
	}
	p.Lifecycle.Append(cell.Hook{
		OnStart: func(ctx cell.HookContext) error {
			return nil
		},
		OnStop: func(hc cell.HookContext) error {
			cancel()
			return nil
		},
	})
	return client, nil
}

func dhcpClient(p Params) dhcp.DHCPClient {
	if !p.Config.EnableGoogleMultiNIC {
		return nil
	}
	return dhcp.NewDHCPClient()
}

func checkCRD(ctx context.Context, clientset k8sClient.Clientset, gvk schema.GroupVersionKind) error {
	if !clientset.IsEnabled() {
		return nil
	}
	crd, err := clientset.ApiextensionsV1().CustomResourceDefinitions().Get(ctx, gvk.GroupKind().String(), metav1.GetOptions{})
	if err != nil {
		return err
	}
	found := false
	for _, v := range crd.Spec.Versions {
		if v.Name == gvk.Version {
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("CRD %q does not have version %q", gvk.GroupKind().String(), gvk.Version)
	}
	return nil
}

var FakeMNClientCell = cell.Module(
	"google-mn-fake-clients",
	"Google Multinetworking Fake Clients",
	cell.Provide(networkResources),
	cell.Provide(gkeNetworkParamSetResources),
	cell.Provide(fakeKubeletClient),
	cell.Provide(fakeNetworkClient),
	cell.Provide(fakeDhcpClient),
)

func fakeKubeletClient() *KubeletClient {
	return &KubeletClient{}
}

func fakeNetworkClient() nwversioned.Interface {
	return nwFake.NewSimpleClientset()
}

type fakeDHCPClient struct{}

func (fakeDHCPClient) GetDHCPResponse(ctx context.Context, containerID, netns, ifname, parentInt string, macAddress *string) (*dhcp.DHCPResponse, error) {
	return &dhcp.DHCPResponse{}, nil
}

func (fakeDHCPClient) Release(ctx context.Context, containerID, netns, ifname string, letLeaseExpire bool) error {
	return nil
}

func (fakeDHCPClient) Renew(ctx context.Context, containerID, netns, ifname, parentIfName string, macAddress *string, clientIP, serverIP net.IP) (*dhcp.DHCPResponse, error) {
	return &dhcp.DHCPResponse{}, nil
}

func fakeDhcpClient() dhcp.DHCPClient {
	return &fakeDHCPClient{}
}
