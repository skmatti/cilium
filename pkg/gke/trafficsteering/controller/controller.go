package controller

import (
	"fmt"
	"net"
	"reflect"
	"time"

	"github.com/cilium/cilium/pkg/gke/apis/trafficsteering/v1alpha1"
	"github.com/cilium/cilium/pkg/gke/client/trafficsteering/clientset/versioned"
	"github.com/cilium/cilium/pkg/gke/client/trafficsteering/clientset/versioned/scheme"
	"github.com/cilium/cilium/pkg/gke/client/trafficsteering/informers/externalversions"
	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/k8s/informer"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/record"
	"k8s.io/klog"

	listers "github.com/cilium/cilium/pkg/gke/client/trafficsteering/listers/trafficsteering/v1alpha1"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	clientv1 "k8s.io/client-go/kubernetes/typed/core/v1"
)

var (
	log = logging.DefaultLogger.WithField(logfields.LogSubsys, "gke-traffic-steering-controller")
)

const (
	// informerSyncPeriod is the period to sync with API server
	informerSyncPeriod = 5 * time.Minute
)

// Controller for traffic steering.
type Controller struct {
	// kubeClient will be used to generate the recorder for events.
	kubeClient kubernetes.Interface

	tsClient         versioned.Interface
	tsLister         listers.TrafficSteeringLister
	tsInformer       cache.SharedIndexInformer
	eventBroadcaster record.EventBroadcaster
	eventRecorder    record.EventRecorder

	podController  cache.Controller
	nodeController cache.Controller

	mu         lock.Mutex
	m          *manager
	nodeLabels map[string]string
}

// NewController returns a new controller for traffic steering.
func NewController(kubeClient kubernetes.Interface, tsClient versioned.Interface, watcherClient *k8s.K8sClient) (*Controller, error) {

	broadcaster := record.NewBroadcaster()
	broadcaster.StartLogging(klog.Infof)
	broadcaster.StartRecordingToSink(&clientv1.EventSinkImpl{Interface: kubeClient.CoreV1().Events("")})
	recorder := broadcaster.NewRecorder(scheme.Scheme, corev1.EventSource{Component: "traffic-steering-controller", Host: nodeTypes.GetName()})

	informerFactory := externalversions.NewSharedInformerFactory(tsClient, informerSyncPeriod)

	c := &Controller{
		kubeClient:       kubeClient,
		tsLister:         informerFactory.Networking().V1alpha1().TrafficSteerings().Lister(),
		tsInformer:       informerFactory.Networking().V1alpha1().TrafficSteerings().Informer(),
		eventBroadcaster: broadcaster,
		eventRecorder:    recorder,
		m:                newManager(),
	}

	_, c.nodeController = informer.NewInformer(
		cache.NewListWatchFromClient(kubeClient.CoreV1().RESTClient(),
			"nodes", corev1.NamespaceAll, fields.ParseSelectorOrDie("metadata.name="+nodeTypes.GetName())),
		&corev1.Node{},
		informerSyncPeriod,
		cache.ResourceEventHandlerFuncs{
			AddFunc:    func(obj interface{}) { c.handleNode(obj) },
			UpdateFunc: func(old, curr interface{}) { c.handleNode(curr) },
		},
		nil,
	)

	c.tsInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    func(obj interface{}) { c.handleTSObj(nil, obj) },
		UpdateFunc: func(old, curr interface{}) { c.handleTSObj(old, curr) },
		DeleteFunc: c.delTSObj,
	})

	_, c.podController = informer.NewInformer(
		cache.NewListWatchFromClient(watcherClient.CoreV1().RESTClient(),
			"pods", corev1.NamespaceAll, fields.ParseSelectorOrDie("spec.nodeName="+nodeTypes.GetName())),
		&slim_corev1.Pod{},
		informerSyncPeriod,
		cache.ResourceEventHandlerFuncs{
			AddFunc:    func(obj interface{}) { c.handlePod(obj) },
			UpdateFunc: func(old, curr interface{}) { c.handlePod(curr) },
			DeleteFunc: c.delPod,
		},
		nil,
	)

	return c, nil
}

func (c *Controller) handleTSObj(old, curr interface{}) {
	log.Debugf("updating TS object: old: %#v", old)
	log.Debugf("updating TS object: current: %#v", curr)

	currTS, ok := curr.(*v1alpha1.TrafficSteering)
	if !ok {
		log.Errorf("invalid type %T", curr)
		return
	}
	scopedLog := log.WithField("name", currTS.Name).WithField("namespace", currTS.Namespace)

	c.mu.Lock()
	defer c.mu.Unlock()

	if old != nil {
		oldTS, ok := old.(*v1alpha1.TrafficSteering)
		if !ok {
			scopedLog.Errorf("invalid old type %T", old)
			return
		}
		if !reflect.DeepEqual(oldTS.Spec, currTS.Spec) {
			// Something changes. Make sure any old entries are cleaned up.
			if err := c.m.delTSConfig(types.NamespacedName{
				Name:      oldTS.GetName(),
				Namespace: oldTS.GetNamespace(),
			}); err != nil {
				c.eventRecorder.Eventf(oldTS, corev1.EventTypeWarning, failedTrafficSteering, err.Error())
			}
		}
	}

	selector, err := toSelector(currTS.Spec.Selector.NodeSelector)
	if err != nil {
		scopedLog.WithError(err).Error("Can't build selector")
		c.eventRecorder.Eventf(currTS, corev1.EventTypeWarning, invalidTrafficSteering, err.Error())
		return
	}
	if selector.Matches(labels.Set(c.nodeLabels)) {
		c.addTS(currTS)
	}
}

// addTS converts the CR to internal config and adds it to manager.
// Must be called with c.mu held.
func (c *Controller) addTS(ts *v1alpha1.TrafficSteering) {
	scopedLog := log.WithField("name", ts.Name).WithField("namespace", ts.Namespace)
	scopedLog.Infof("Applying TrafficSteering on the node")
	cfg, err := parse(ts)
	if err != nil {
		scopedLog.WithError(err).Error("TrafficSteering object is invalid")
		c.eventRecorder.Eventf(ts, corev1.EventTypeWarning, invalidTrafficSteering, err.Error())
		return
	}
	if err := c.m.addTSConfig(cfg); err != nil {
		scopedLog.WithError(err).Error("Failed to apply TrafficSteering")
		msg := fmt.Sprintf("failed to apply TrafficSteering on node %q: %v", nodeTypes.GetName(), err)
		c.eventRecorder.Eventf(ts, corev1.EventTypeWarning, failedTrafficSteering, msg)
		return
	}

	c.eventRecorder.Eventf(ts, corev1.EventTypeNormal, appliedTrafficSteering, fmt.Sprintf("Applied TrafficSteering on node %q (resourceVersion = %s) ", nodeTypes.GetName(), ts.ResourceVersion))
}

func (c *Controller) delTSObj(obj interface{}) {
	log.Debugf("deleting TS object: %#v", obj)
	ts, ok := obj.(*v1alpha1.TrafficSteering)
	if !ok {
		deletedObj, deletedOk := obj.(cache.DeletedFinalStateUnknown)
		if deletedOk {
			ts, ok = deletedObj.Obj.(*v1alpha1.TrafficSteering)
		}
		if !ok {
			log.Warningf("Cannot recover the deleted TrafficSteering obj %v", obj)
			return
		}
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	scopedLog := log.WithField("name", ts.Name).WithField("namespace", ts.Namespace)
	scopedLog.Info("Disabling TrafficSteering")
	c.m.delTSConfig(types.NamespacedName{
		Namespace: ts.Namespace,
		Name:      ts.Name,
	})
}

func ipOf(pod *slim_corev1.Pod) (net.IP, error) {
	ip := net.ParseIP(pod.Status.PodIP)
	if ip == nil {
		return nil, fmt.Errorf("invalid pod IP %q", pod.Status.PodIP)
	}
	if ip.To4() == nil {
		return nil, fmt.Errorf("doesn't support non-ipv4 pod %q: %s", pod.GetName(), pod.Status.PodIP)
	}
	return ip.To4(), nil
}

func (c *Controller) handlePod(curr interface{}) {
	log.Debugf("updating POD: %#v", curr)
	pod := k8s.ObjTov1Pod(curr)
	if pod == nil {
		return
	}
	if pod.Spec.HostNetwork {
		return
	}
	scopedLog := log.WithField("name", pod.Name).WithField("namespace", pod.Namespace)
	podIP, err := ipOf(pod)
	if err != nil {
		scopedLog.WithError(err).Error("failed to extract pod IP")
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	// Assuming pod IP doesn't change, no need to delete first.
	if err := c.m.addPodIP(podIP); err != nil {
		scopedLog.WithError(err).Error("Failed to add pod IP")
	}
}

func (c *Controller) delPod(obj interface{}) {
	log.Debugf("deleting POD: %#v", obj)
	pod := k8s.ObjTov1Pod(obj)
	if pod == nil {
		return
	}
	scopedLog := log.WithField("name", pod.Name).WithField("namespace", pod.Namespace)
	podIP, err := ipOf(pod)
	if err != nil {
		scopedLog.WithError(err).Error("failed to extract pod IP")
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	c.m.delPodIP(podIP)
}

func toSelector(selector *metav1.LabelSelector) (labels.Selector, error) {
	if selector == nil {
		return labels.Everything(), nil
	}
	return metav1.LabelSelectorAsSelector(selector)
}

func (c *Controller) handleNode(curr interface{}) {
	log.Debugf("updating Node: %#v", curr)

	currNode := k8s.ObjToV1Node(curr)
	if currNode == nil {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if reflect.DeepEqual(c.nodeLabels, currNode.GetLabels()) {
		// labels not change
		return
	}

	allTSObjs, err := c.tsLister.List(labels.Everything())
	if err != nil {
		log.WithError(err).Error("Failed to list existing TrafficSteering objects")
		return
	}

	for _, ts := range allTSObjs {
		scopedLog := log.WithField("name", ts.Name).WithField("namespace", ts.Namespace)
		selector, err := toSelector(ts.Spec.Selector.NodeSelector)
		if err != nil {
			scopedLog.WithError(err).Error("Can't build selector")
			c.eventRecorder.Eventf(ts, corev1.EventTypeWarning, invalidTrafficSteering, err.Error())
			continue
		}
		if selector.Matches(labels.Set(currNode.GetLabels())) {
			c.addTS(ts)
		} else {
			scopedLog.Info("Disabling TrafficSteering")
			if err := c.m.delTSConfig(types.NamespacedName{
				Namespace: ts.Namespace,
				Name:      ts.Name,
			}); err != nil {
				c.eventRecorder.Eventf(ts, corev1.EventTypeWarning, failedTrafficSteering, err.Error())
			}
		}
	}

	c.nodeLabels = currNode.GetLabels()
}

// Run starts the controller and waits for stop.
func (c *Controller) Run() {
	log.Info("Starting traffic steering controller")
	go c.nodeController.Run(wait.NeverStop)
	if ok := cache.WaitForNamedCacheSync("nodes", wait.NeverStop, c.nodeController.HasSynced); !ok {
		log.Error("Failed to wait for node caches to sync")
		return
	}
	go c.tsInformer.Run(wait.NeverStop)
	if ok := cache.WaitForNamedCacheSync("trafficsteering", wait.NeverStop, c.tsInformer.HasSynced); !ok {
		log.Error("Failed to wait for trafficsteering caches to sync")
		return
	}
	go c.podController.Run(wait.NeverStop)
	if ok := cache.WaitForNamedCacheSync("pods", wait.NeverStop, c.podController.HasSynced); !ok {
		log.Error("Failed to wait for pod caches to sync")
		return
	}
	<-wait.NeverStop
	log.Info("Shutting down traffic steering controller")
	return
}

// Init initializes the traffic steering controller.
func Init() (*Controller, error) {
	kubeConfig, err := k8s.CreateConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to create k8s configuration: %v", err)
	}

	kubeClient, err := kubernetes.NewForConfig(kubeConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create kube client: %v", err)
	}

	tsClient, err := versioned.NewForConfig(kubeConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create traffic steering client: %v", err)
	}

	tsController, err := NewController(kubeClient, tsClient, k8s.WatcherClient())
	if err != nil {
		return nil, fmt.Errorf("failed to instantiate traffic steering controller %v", err)
	}
	go tsController.Run()
	return tsController, nil
}
