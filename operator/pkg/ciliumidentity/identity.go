package ciliumidentity

import (
	"context"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/util/workqueue"

	"github.com/cilium/cilium/operator/metrics"
	operatorOption "github.com/cilium/cilium/operator/option"
	"github.com/cilium/cilium/operator/watchers"
	cilium_api_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

func (c *Controller) subscribeToCIDEvents() {
	watchers.SubscribeToCIDAddEvents(c.onCiliumIdentityUpsertEvent)
	watchers.SubscribeToCIDUpdateEvents(c.onCiliumIdentityUpsertEvent)
	watchers.SubscribeToCIDDeleteEvents(c.onCiliumIdentityDeleteEvent)
}

func (c *Controller) onCiliumIdentityUpsertEvent(cid *cilium_api_v2.CiliumIdentity) {
	// Remove deletion mark when upsert event is received for a CID that was
	// marked for deletion. It means some source other than CID controller in
	// cilium-operator is writing to CIDs.
	c.reconciler.cidDeletionTracker.Unmark(cid.Name)

	c.enqueueCIDReconciliation(cidResourceKey(cid.Name), 0)
}

func (c *Controller) onCiliumIdentityDeleteEvent(cid *cilium_api_v2.CiliumIdentity) {
	c.enqueueCIDReconciliation(cidResourceKey(cid.Name), 0)
}

func (c *Controller) initCIDQueue() {
	log.WithFields(logrus.Fields{
		logfields.WorkQueueSyncBackOff: defaultSyncBackOff,
	}).Info("CID controller workqueue configuration for Cilium Identity")

	c.cidQueue = workqueue.NewNamedRateLimitingQueue(workqueue.NewItemExponentialFailureRateLimiter(defaultSyncBackOff, maxSyncBackOff), "cilium_identity")
}

// runWorker runs a worker thread that just dequeues items, processes them, and
// marks them done. You may run as many of these in parallel as you wish; the
// workqueue guarantees that they will not end up processing the same CID
// at the same time
func (c *Controller) runCIDWorker() {
	log.Infof("Starting CID worker in CID controller")
	defer log.Infof("Stopping CID worker in CID controller")

	for c.processNextCIDQueueItem() {
		select {
		case <-c.context.Done():
			return
		case <-c.stopCh:
			return
		default:
		}
	}
}

func (c *Controller) processNextCIDQueueItem() bool {
	processingStartTime := time.Now()

	item, quit := c.cidQueue.Get()
	if quit {
		return false
	}
	defer c.cidQueue.Done(item)

	cidKey := item.(resource.Key)
	err := c.reconciler.reconcileCID(cidKey)
	c.handleCIDErr(err, item)

	if operatorOption.Config.EnableMetrics {
		enqueueTime, exists := c.cidEnqueuedAt.GetEnqueueTimeAndReset(cidKey.String())
		if exists {
			enqueuedLatency := processingStartTime.Sub(enqueueTime).Seconds()
			metrics.CIDControllerWorkqueueLatency.WithLabelValues(metrics.LabelValueCIDWorkqueue, metrics.LabelValueEnqueuedLatency).Observe(enqueuedLatency)
		}
		processingLatency := time.Since(processingStartTime).Seconds()
		metrics.CIDControllerWorkqueueLatency.WithLabelValues(metrics.LabelValueCIDWorkqueue, metrics.LabelValueProcessingLatency).Observe(processingLatency)
	}

	return true
}

func (c *Controller) handleCIDErr(err error, item interface{}) {
	if err == nil {
		if operatorOption.Config.EnableMetrics {
			metrics.CIDControllerWorkqueueEventCount.WithLabelValues(metrics.LabelValueCIDWorkqueue, metrics.LabelValueOutcomeSuccess).Inc()
		}

		c.cidQueue.Forget(item)
		return
	}

	if operatorOption.Config.EnableMetrics {
		metrics.CIDControllerWorkqueueEventCount.WithLabelValues(metrics.LabelValueCIDWorkqueue, metrics.LabelValueOutcomeFail).Inc()
	}

	log.WithField(logfields.CIDName, item).Errorf("Failed to process Cilium Identity: %v", err)

	if c.cidQueue.NumRequeues(item) < maxProcessRetries {
		c.cidQueue.AddRateLimited(item)
		return
	}

	// Drop the CID from queue, we maxed out retries.
	log.WithError(err).WithFields(logrus.Fields{
		logfields.CIDName: item,
	}).Error("Dropping the Cilium Identity from queue, exceeded maxRetries")
	c.cidQueue.Forget(item)
}

func cidResourceKey(cidName string) resource.Key {
	return resource.Key{Name: cidName}
}

func (c *Controller) enqueueCIDReconciliation(cidKey resource.Key, delay time.Duration) {
	if len(cidKey.String()) == 0 {
		return
	}

	c.cidEnqueuedAt.SetEnqueueTimeIfNotSet(cidKey.String())
	c.cidQueue.AddAfter(cidKey, delay)
}

func GetIDRelevantLabelsFromConfigMap(ctx context.Context, clientset k8sClient.Clientset) ([]string, error) {
	maxRetries := 5
	waitDuration := 1 * time.Second
	attempt := 1

	var cm *corev1.ConfigMap
	var err error
	for attempt <= maxRetries {
		cm, err = clientset.CoreV1().ConfigMaps(metav1.NamespaceSystem).Get(ctx, ciliumConfigMapName, metav1.GetOptions{})
		if err == nil {
			break
		}

		time.Sleep(waitDuration)
		attempt++
	}

	if err != nil {
		return nil, err
	}

	// Turns a string into a string slice. Whitespaces separate filter entries.
	// https://docs.cilium.io/en/stable/operations/performance/scalability/identity-relevant-labels/
	filter := strings.Fields(cm.Data[idRelevantLabelsKey])
	log.Infof("Identity relevant labels filter retrieved from %s ConfigMap: %v", ciliumConfigMapName, filter)

	return filter, nil
}
