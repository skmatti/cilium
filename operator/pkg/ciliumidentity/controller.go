package ciliumidentity

import (
	"context"
	"fmt"
	"time"

	"github.com/cilium/workerpool"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/util/workqueue"

	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

var log = logging.DefaultLogger.WithField(logfields.LogSubsys, "cilium-identity-controller")

const (
	ciliumConfigMapName = "cilium-config"
	idRelevantLabelsKey = "labels"

	// defaultSyncBackOff is the default backoff period for cesSync calls.
	defaultSyncBackOff = 1 * time.Second
	// maxSyncBackOff is the max backoff period for cesSync calls.
	maxSyncBackOff = 100 * time.Second
	// maxRetries is the number of times a cesSync will be retried before it is
	// dropped out of the queue.
	maxProcessRetries = 15
	// cidDeleteDelay is the delay to enqueue another CID event to be reconciled
	// after CID is marked for deletion. This is required for simultaneous CID
	// management by both cilium-operator and cilium-agent. Without the delay,
	// operator might immediately clean up CIDs created by agent, before agent can
	// finish CEP creation.
	cidDeleteDelay = 30 * time.Second
)

type Controller struct {
	context context.Context
	stopCh  <-chan struct{}

	clientset  k8sClient.Clientset
	reconciler *reconciler

	// Work queues are used to sync resources with the api-server.
	// Work queues will rate-limit requests going to api-server, ensures a single
	// resource key will not be processed multiple times concurrently, and if
	// a resource key is added multiple times before it can be processed, this
	// will only be processed once.
	cidQueue workqueue.RateLimitingInterface
	podQueue workqueue.RateLimitingInterface

	cidEnqueuedAt *EnqueueTimeTracker
	podEnqueuedAt *EnqueueTimeTracker

	wp *workerpool.WorkerPool

	cesEnabled            bool
	googleMultiNICEnabled bool
}

type queueOperations interface {
	enqueueCIDReconciliation(cidKey resource.Key, delay time.Duration)
	enqueuePodReconciliation(podKey resource.Key, delay time.Duration)
}

func NewCIDController(
	ctx context.Context,
	clientset k8sClient.Clientset,
	cesEnabled bool,
	googleMultiNICEnabled bool,
) *Controller {
	cidController := &Controller{
		context:               ctx,
		clientset:             clientset,
		cidEnqueuedAt:         &EnqueueTimeTracker{enqueuedAt: make(map[string]time.Time)},
		podEnqueuedAt:         &EnqueueTimeTracker{enqueuedAt: make(map[string]time.Time)},
		cesEnabled:            cesEnabled,
		googleMultiNICEnabled: googleMultiNICEnabled,
	}

	cidController.reconciler = newReconciler(
		clientset,
		cesEnabled,
		googleMultiNICEnabled,
		cidController,
	)

	cidController.initializeQueues()
	cidController.subscribeToEvents()

	return cidController
}

func (c *Controller) Run(stopCh <-chan struct{}) error {
	log.Info("Starting Cilium Identity controller")
	defer utilruntime.HandleCrash()
	defer c.cidQueue.ShutDown()
	defer c.podQueue.ShutDown()

	c.stopCh = stopCh

	// The desired state needs to be calculated before the events are processed.
	if err := c.reconciler.calcDesiredStateOnStartup(); err != nil {
		return fmt.Errorf("CID controller failed to calculate the desired state: %v", err)
	}

	// The Cilium Identity (CID) controller running in cilium-operator is
	// responsible only for managing CID API objects.
	//
	// Pod events are added to Pod workqueue.
	// Namespace events are processed immediately and added also to Pod workqueue.
	// CID events are added to CID workqueue.
	// Processing Pod workqueue items are adding items to CID workqueue.
	// Processed CID workqueue items result in mutations to CID API objects.
	//
	// Diagram:
	//-----------------------Pod event--------CID event
	//-------------------------||---------------||
	//--------------------------V----------------V
	// Namespace event -> Pod workqueue -> CID workqueue -> Mutate CID API objects
	log.Info("Starting CID controller reconciler.")
	c.startWorkQueues()

	go func() {
		defer utilruntime.HandleCrash()
	}()

	<-stopCh

	return nil
}

func (c *Controller) initializeQueues() {
	c.initCIDQueue()
	c.initPodQueue()
}

func (c *Controller) subscribeToEvents() {
	c.subscribeToCIDEvents()
	c.subscribeToPodEvents()
	c.subscribeToNamespaceEvents()
	c.subscribeToCESEvents()
}

func (c *Controller) startWorkQueues() {
	go c.runCIDWorker()
	go c.runPodWorker()
}
