package clustermesh

import (
	"fmt"
	"strings"

	networkv1 "github.com/GoogleCloudPlatform/gke-networking-api/apis/network/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/tools/cache"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	ciliumio "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/informer"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_labels "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/labels"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/selection"
	"github.com/cilium/cilium/pkg/k8s/types"
	"github.com/cilium/cilium/pkg/k8s/utils"
	"github.com/cilium/cilium/pkg/labels"
)

const (
	multinicAnnotation = "networking.gke.io/multinic"
	networkNameLabel   = "k8s:networking.gke.io/network"
)

// googleSyncer is responsible for Google-specific logic for synchronizing
// resources to the clustermesh.
type googleSyncer struct {
	namespaceCache  cache.Store
	syncMultiNicEPs bool
}

// newGoogleSyncer creates a new GoogleSyncer.
func newGoogleSyncer(ginfo cmtypes.GoogleConfig, clientset k8sClient.Clientset) (*googleSyncer, error) {
	s := &googleSyncer{
		syncMultiNicEPs: ginfo.SyncMultiNicEPs,
	}

	// We only need to watch namespaces if some label restrictions are configured.
	// Otherwise we sync everything.
	if len(ginfo.NamespaceLabels) > 0 {
		var err error
		s.namespaceCache, err = newNamespaceCache(clientset, ginfo.NamespaceLabels)
		if err != nil {
			return nil, fmt.Errorf("failed to watch namespaces: %w", err)
		}
	}

	return s, nil
}

func (gs *googleSyncer) ShouldSyncNamespace(namespace string) bool {
	if gs.namespaceCache == nil {
		return true
	}

	nsName := &slim_corev1.Namespace{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name: namespace,
		},
	}
	_, exists, err := gs.namespaceCache.Get(nsName)
	if err != nil {
		log.WithError(err).Errorf("failed to get namespace %q from cache", nsName)
		return false
	}

	return exists
}

func (gs *googleSyncer) ShouldSyncIdentity(identity *ciliumv2.CiliumIdentity) bool {
	if !gs.syncMultiNicEPs {
		return false
	}
	if identity == nil {
		return false
	}

	if network, ok := identity.SecurityLabels[networkNameLabel]; ok {
		if !networkv1.IsDefaultNetwork(network) {
			log.Debugf("Found multinic identity for endpoint %s", identity.Name)
			return true
		}
	}
	return false
}

func (gs *googleSyncer) ShouldSyncCEP(ep *types.CiliumEndpoint) bool {
	if !gs.syncMultiNicEPs {
		return false
	}
	if ep == nil {
		return false
	}

	if _, ok := ep.Annotations[multinicAnnotation]; ok {
		log.Debugf("Found multinic label for endpoint %s", ep.Name)
		return true
	}
	return false
}

func newNamespaceCache(clientset k8sClient.Clientset, labels []string) (cache.Store, error) {
	labelSelector, err := buildLabelSelector(labels)
	if err != nil {
		return nil, fmt.Errorf("failed to build label selector from %v: %w", labels, err)
	}

	listOpts := func(options *metav1.ListOptions) {
		options.LabelSelector = labelSelector.String()
	}
	var namespaceInformer cache.Controller
	var nsCache cache.Store
	nsCache, namespaceInformer = informer.NewInformer(
		utils.ListerWatcherWithModifier(
			utils.ListerWatcherFromTyped[*slim_corev1.NamespaceList](clientset.Slim().CoreV1().Namespaces()), listOpts),
		&slim_corev1.Namespace{},
		0,
		cache.ResourceEventHandlerFuncs{},
		nil,
	)

	go namespaceInformer.Run(wait.NeverStop)
	if ok := cache.WaitForNamedCacheSync("clustermesh-apiserver", wait.NeverStop, namespaceInformer.HasSynced); !ok {
		return nil, fmt.Errorf("failed to wait for namespace cache to sync")
	}
	return nsCache, nil
}

func buildLabelSelector(labels []string) (slim_labels.Selector, error) {
	labelSelector := slim_labels.NewSelector()
	for _, label := range labels {
		labelNameSelector, err := slim_labels.NewRequirement(label, selection.Exists, nil)
		if err != nil {
			return nil, err
		}
		labelSelector = labelSelector.Add(*labelNameSelector)
	}
	return labelSelector, nil
}

func getIdentityNamespace(identity *ciliumv2.CiliumIdentity) (string, error) {
	l := strings.TrimSuffix(labels.GenerateK8sLabelString(ciliumio.PodNamespaceLabel, ""), "=")

	ns, found := identity.SecurityLabels[l]
	if !found {
		return "", fmt.Errorf("namespace label %q not found on identity %q", ciliumio.PodNamespaceLabel, identity.Name)
	}

	return ns, nil
}
