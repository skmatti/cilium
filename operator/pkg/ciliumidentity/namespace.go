package ciliumidentity

import (
	"github.com/cilium/cilium/operator/watchers"
	ciliumio "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_core_v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/labelsfilter"
	"github.com/cilium/cilium/pkg/policy"
)

func (c *Controller) subscribeToNamespaceEvents() {
	watchers.SubscribeToNSUpdateEvents(c.onNamespaceUpdate)
}

func (c *Controller) onNamespaceUpdate(nsNew, nsOld *slim_core_v1.Namespace) {
	newLabels := getNamespaceLabels(nsNew)
	oldLabels := getNamespaceLabels(nsOld)

	newIdtyLabels, _ := labelsfilter.Filter(newLabels)
	oldIdtyLabels, _ := labelsfilter.Filter(oldLabels)

	// Do not perform any other operations if labels did not change.
	if oldIdtyLabels.DeepEqual(&newIdtyLabels) {
		return
	}

	log.Infof("Labels changed for namespace: %s", nsNew.Name)
	c.reconciler.reconcileNS(nsResourceKey(nsNew.Name))
}

func getNamespaceLabels(ns *slim_core_v1.Namespace) labels.Labels {
	lbls := ns.GetLabels()
	labelMap := make(map[string]string, len(lbls))
	for k, v := range lbls {
		labelMap[policy.JoinPath(ciliumio.PodNamespaceMetaLabels, k)] = v
	}
	return labels.Map2Labels(labelMap, labels.LabelSourceK8s)
}

func nsResourceKey(namespace string) resource.Key {
	return resource.Key{Name: namespace}
}
