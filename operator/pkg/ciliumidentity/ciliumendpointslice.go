package ciliumidentity

import (
	"strconv"

	"github.com/cilium/cilium/operator/pkg/ciliumendpointslice"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
)

func (c *Controller) subscribeToCESEvents() {
	if !c.cesEnabled {
		return
	}

	ciliumendpointslice.SubscribeToCESAddEvent(c.onCiliumEndpointSliceUpdate)
	ciliumendpointslice.SubscribeToCESUpdateEvent(c.onCiliumEndpointSliceUpdate)
	ciliumendpointslice.SubscribeToCESDeleteEvent(c.onCiliumEndpointSliceDelete)
}

func (c *Controller) onCiliumEndpointSliceUpdate(ces *v2alpha1.CiliumEndpointSlice) {
	if ces == nil {
		return
	}

	cidsWithNoCESUsage := c.reconciler.cidUsageInCES.ProcessCESUpsert(ces.Name, ces.Endpoints)

	for _, cid := range cidsWithNoCESUsage {
		cidName := strconv.Itoa(int(cid))

		log.Infof("Reconciling Cilium Identity %s because it is no longer used in CESs", cidName)
		c.enqueueCIDReconciliation(cidResourceKey(cidName), 0)
	}
}

func (c *Controller) onCiliumEndpointSliceDelete(ces *v2alpha1.CiliumEndpointSlice) {
	if ces == nil {
		return
	}

	cidsWithNoCESUsage := c.reconciler.cidUsageInCES.ProcessCESDelete(ces.Name, ces.Endpoints)

	for _, cid := range cidsWithNoCESUsage {
		cidName := strconv.Itoa(int(cid))

		log.Infof("Reconciling Cilium Identity %s because it is no longer used in CESs", cidName)
		c.enqueueCIDReconciliation(cidResourceKey(cidName), 0)
	}
}
