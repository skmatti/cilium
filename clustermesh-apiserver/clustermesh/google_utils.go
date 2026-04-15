package clustermesh

import (
	"context"
	"fmt"
	"maps"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"

	cmconfig "github.com/cilium/cilium/pkg/clustermesh/config"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/informer"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_labels "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/labels"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/k8s/types"
	"github.com/cilium/cilium/pkg/k8s/utils"
	"github.com/cilium/cilium/pkg/labels"
)

// googleSyncer holds google-specific sync logic and configuration.
type googleSyncer struct {
	namespaceCache         cache.Store
	endpointSelectors      []slim_labels.Selector
	overrideIdentityLabels map[string]string
}

// newGoogleSyncer creates a new GoogleSyncer.
func newGoogleSyncer(ctx context.Context, ginfo cmconfig.GoogleConfig, clientset k8sClient.Clientset, onNamespaceUpdate func(ns string)) (*googleSyncer, error) {
	s := &googleSyncer{
		overrideIdentityLabels: ginfo.OverrideIdentityLabels,
	}

	var err error
	s.endpointSelectors, err = parseLabelSelectors(ginfo.EndpointLabelSelectors)
	if err != nil {
		return nil, fmt.Errorf("build label selectors from %v: %w", ginfo.EndpointLabelSelectors, err)
	}
	log.WithField("labelSelectors", s.endpointSelectors).Info("Parsed label selectors for endpoint and identity sync")

	// We only need to watch namespaces if some label restrictions are configured.
	// Otherwise we sync everything.
	if len(ginfo.ServiceNamespaceLabels) > 0 {
		namespaceCache, err := newNamespaceCache(ctx, clientset, ginfo.ServiceNamespaceLabels, onNamespaceUpdate)
		if err != nil {
			return nil, fmt.Errorf("watch namespaces: %w", err)
		}
		s.namespaceCache = namespaceCache
	}

	return s, nil
}

func (s *googleSyncer) ShouldSyncNamespace(namespace string) bool {
	if s.namespaceCache == nil {
		return true
	}

	nsName := &slim_corev1.Namespace{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name: namespace,
		},
	}
	_, exists, err := s.namespaceCache.Get(nsName)
	if err != nil {
		log.WithError(err).Errorf("failed to get namespace %q from cache", nsName)
		return false
	}

	return exists
}

func (s *googleSyncer) ShouldSyncIdentity(identity *ciliumv2.CiliumIdentity) bool {
	if identity == nil {
		return false
	}

	return s.shouldSyncLabels(labels.Map2Labels(identity.SecurityLabels, labels.LabelSourceK8s).K8sStringMap())
}

func (s *googleSyncer) ShouldSyncCEP(ep *types.CiliumEndpoint) bool {
	if ep == nil || ep.Identity == nil {
		return false
	}

	return s.shouldSyncLabels(labels.NewLabelsFromModel(ep.Identity.Labels).K8sStringMap())
}

// OverrideIdentityLabels overrides the given security labels with the configured override labels.
func (s *googleSyncer) OverrideIdentityLabels(securityLabels map[string]string) map[string]string {
	if len(s.overrideIdentityLabels) == 0 {
		return securityLabels
	}

	newLabels := make(map[string]string, len(securityLabels)+len(s.overrideIdentityLabels))
	maps.Copy(newLabels, securityLabels)
	maps.Copy(newLabels, s.overrideIdentityLabels)
	return newLabels
}

// shouldSyncLabels checks if the labels of an identity or endpoint should be synced based on the configured selectors.
// It returns true if at least one of the selectors matches the labels, and false otherwise.
func (s *googleSyncer) shouldSyncLabels(labels map[string]string) bool {
	if len(s.endpointSelectors) == 0 {
		return true
	}
	endpointLabels := slim_labels.Set(labels)

	// Loop through requirements with OR operator
	for _, selector := range s.endpointSelectors {

		// Matches set of AND requirement selectors
		if selector.Matches(endpointLabels) {
			return true
		}
	}
	return false
}

func newNamespaceCache(ctx context.Context, clientset k8sClient.Clientset, labels []string, onNamespaceUpdate func(ns string)) (cache.Store, error) {
	labelSelectorStr := strings.Join(labels, ",")
	labelSelector, err := slim_labels.Parse(labelSelectorStr)
	if err != nil {
		return nil, fmt.Errorf("parse %q as label selector: %w", labelSelectorStr, err)
	}
	log.WithField("labelSelector", labelSelectorStr).Info("Parsed label selector for namespace sync")

	listOpts := func(options *metav1.ListOptions) {
		options.LabelSelector = labelSelector.String()
	}
	var namespaceInformer cache.Controller
	var nsCache cache.Store

	nsHandler := cache.ResourceEventHandlerFuncs{}
	if onNamespaceUpdate != nil {
		nsHandler.AddFunc = func(obj interface{}) {
			if ns, ok := obj.(*slim_corev1.Namespace); ok {
				onNamespaceUpdate(ns.Name)
			}
		}
		nsHandler.UpdateFunc = func(oldObj, newObj interface{}) {
			if ns, ok := newObj.(*slim_corev1.Namespace); ok {
				onNamespaceUpdate(ns.Name)
			}
		}
		nsHandler.DeleteFunc = func(obj interface{}) {
			ns, ok := obj.(*slim_corev1.Namespace)
			if !ok {
				tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
				if !ok {
					return
				}
				ns, ok = tombstone.Obj.(*slim_corev1.Namespace)
				if !ok {
					return
				}
			}
			onNamespaceUpdate(ns.Name)
		}
	}

	nsCache, namespaceInformer = informer.NewInformer(
		utils.ListerWatcherWithModifier(
			utils.ListerWatcherFromTyped[*slim_corev1.NamespaceList](clientset.Slim().CoreV1().Namespaces()), listOpts),
		&slim_corev1.Namespace{},
		0,
		nsHandler,
		nil,
	)

	go namespaceInformer.Run(ctx.Done())
	if ok := cache.WaitForNamedCacheSync("clustermesh-apiserver", ctx.Done(), namespaceInformer.HasSynced); !ok {
		return nil, fmt.Errorf("wait for namespace cache to sync")
	}
	return nsCache, nil
}

func parseLabelSelectors(labelSelectorStrs []string) ([]slim_labels.Selector, error) {
	var selectors []slim_labels.Selector
	for _, selectorStr := range labelSelectorStrs {
		selector, err := slim_labels.Parse(selectorStr)
		if err != nil {
			return nil, fmt.Errorf("parse %q as label selector: %w", selectorStr, err)
		}
		selectors = append(selectors, selector)
	}
	return selectors, nil
}
