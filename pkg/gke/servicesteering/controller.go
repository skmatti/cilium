package servicesteering

import (
	"context"
	"errors"
	"fmt"
	"net"

	"github.com/cilium/cilium/api/v1/models"
	agentK8s "github.com/cilium/cilium/daemon/k8s"
	"github.com/cilium/cilium/pkg/datapath/connector"
	"github.com/cilium/cilium/pkg/ebpf"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maps/sfc"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/time"
	"github.com/cilium/cilium/pkg/trigger"
	"github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"

	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	networkv1 "github.com/GoogleCloudPlatform/gke-networking-api/apis/network/v1"
	daemonclient "github.com/cilium/cilium/pkg/client"
	ciliumio "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	v1 "gke-internal.googlesource.com/anthos-networking/apis/v2/service-steering/v1"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
)

var (
	sfclog             = logging.DefaultLogger.WithField(logfields.LogSubsys, "sfc")
	reconcileLock      = lock.Mutex{}
	minTriggerInternal = time.Second * 2
	resyncInterval     = time.Minute * 10
	scheme             = runtime.NewScheme()
	geneveDevName      = "gke_ss_geneve"
)

func init() {
	utilruntime.Must(corev1.AddToScheme(scheme))
	utilruntime.Must(v1.AddToScheme(scheme))
	utilruntime.Must(networkv1.AddToScheme(scheme))
}

func runServiceSteeringController(ctx context.Context, p params) error {
	logWriter := sfclog.Writer()
	mgr, err := ctrl.NewManager(p.Clientset.RestConfig(), ctrl.Options{
		Scheme: scheme,
		Metrics: metricsserver.Options{
			BindAddress: "0",
		},
		Logger: zap.New(zap.ConsoleEncoder(), zap.WriteTo(logWriter)),
		Cache: cache.Options{
			SyncPeriod: &resyncInterval,
			ByObject: map[client.Object]cache.ByObject{
				&corev1.Service{}: {
					Label: labels.SelectorFromSet(labels.Set{v1.ManagedByKey: v1.ControllerName}),
				},
				&v1.TrafficSelector{}:      {},
				&v1.ServiceFunctionChain{}: {},
				&networkv1.Network{}:       {},
			},
		},
	})
	if err != nil {
		return fmt.Errorf("failed to create service steering controller manager: %v", err)
	}

	// Initialize service steering controllers
	reconciler, err := NewReconciler(ctx, mgr.GetClient(), p.EpManager, p.Resources, p.Metrics)
	if err != nil {
		return fmt.Errorf("failed to create service steering reconciler: %v", err)
	}
	reconciler.subscribeResourceEvents(ctx)

	err = ctrl.NewControllerManagedBy(mgr).
		For(&v1.ServiceFunctionChain{}, builder.WithPredicates(predicate.NewPredicateFuncs(isValidSFC))).
		Watches(
			&v1.TrafficSelector{},
			handler.EnqueueRequestsFromMapFunc(mapTStoSFC),
		).
		Owns(&corev1.Service{}, builder.WithPredicates(predicate.NewPredicateFuncs(isValidSvc))).
		Complete(reconciler)
	if err != nil {
		return fmt.Errorf("failed to setup service steering controller: %v", err)
	}
	sfclog.Info("Starting service steering controller manager")
	go func() {
		if err := mgr.Start(ctx); err != nil {
			sfclog.WithError(err).Error("Failed to run service steering controller manager")
		}
		sfclog.Info("Stopped service steering controller manager")
	}()

	return nil
}

type ServiceSteeringReconciler struct {
	client.Client
	EpManager      endpointmanager.EndpointManager
	podStore       resource.Store[*slim_corev1.Pod]
	namespaceStore resource.Store[*slim_corev1.Namespace]
	resources      agentK8s.Resources
	selectorCache  []extractedSelector
	epTrigger      *trigger.Trigger
	cp             configPatcher
	metrics        sfcMetrics
}

type configPatcher interface {
	ConfigPatch(cfg models.DaemonConfigurationSpec) error
}

type extractedSelector struct {
	*v1.TrafficSelector
	nsSelector    labels.Selector
	podSelector   labels.Selector
	cidr          net.IPNet
	networkID     uint32
	portSelectors map[portSelector]struct{}
	entry         sfc.SelectEntry
	serviceIP     net.IP
}

// initDataPathOption set the option.GoogleServiceSteeringDataPath based on if PathMap is empty.
// It must be called before endpoint regeneration on startup.
func initDataPathOption() error {
	enable := !isPathMapEmpty()
	if enable {
		if err := addGeneveDev(geneveDevName, sfclog); err != nil {
			// Non-fatal error
			sfclog.Warningf("Init: failed to add geneve dev %s: %v", geneveDevName, err)
			return nil
		}
	} else {
		if err := removeDevice(geneveDevName, sfclog); err != nil {
			return err
		}
	}
	option.Config.Opts.SetBool(option.GoogleServiceSteeringDataPath, enable)
	sfclog.Infof("Init: Set %s to %s", option.GoogleServiceSteeringDataPath, optString(enable))
	return nil
}

func isPathMapEmpty() bool {
	err := sfc.PathMap.NextKey(nil, &sfc.PathKey{})
	return errors.Is(err, ebpf.ErrKeyNotExist)
}

func NewReconciler(ctx context.Context, client client.Client, epManager endpointmanager.EndpointManager, resources agentK8s.Resources, metrics sfcMetrics) (*ServiceSteeringReconciler, error) {
	cl, err := daemonclient.NewClient("")
	if err != nil {
		return nil, fmt.Errorf("failed to create Daemon client: %v", err)
	}

	podStore, err := resources.LocalPods.Store(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to retreive local pod store: %v", err)
	}
	namespaceStore, err := resources.Namespaces.Store(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to retreive namespace store: %v", err)
	}

	r := ServiceSteeringReconciler{
		Client:         client,
		EpManager:      epManager,
		resources:      resources,
		podStore:       podStore,
		namespaceStore: namespaceStore,
		cp:             cl,
		metrics:        metrics,
	}

	// Use a trigger function for endpoint updates to avoid blocking the endpoint manager.
	rt, err := trigger.NewTrigger(trigger.Parameters{
		Name:        "service-steering-endpoint-trigger",
		MinInterval: minTriggerInternal,
		TriggerFunc: r.handleTriggerEvent,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to initialize endpoint trigger function: %v", err)
	}
	r.epTrigger = rt
	return &r, nil
}

func (r *ServiceSteeringReconciler) subscribeResourceEvents(ctx context.Context) {
	sfclog.Debugln("Observing namespace events")
	r.resources.Namespaces.Observe(ctx, func(e resource.Event[*slim_corev1.Namespace]) {
		reason := fmt.Sprintf("namespace:%s", e.Key.Name)
		r.epTrigger.TriggerWithReason(reason)
		e.Done(nil)
	}, func(err error) {
		if err != nil {
			sfclog.WithError(err).Error("Namespace event stream terminated")
		}
	})

	sfclog.Debugln("Observing local pod events")
	r.resources.LocalPods.Observe(ctx, func(e resource.Event[*slim_corev1.Pod]) {
		reason := fmt.Sprintf("pod:%s/%s", e.Key.Namespace, e.Key.Name)
		r.epTrigger.TriggerWithReason(reason)
		e.Done(nil)
	}, func(err error) {
		if err != nil {
			sfclog.WithError(err).Error("Local pod event stream terminated")
		}
	})
}

func (r *ServiceSteeringReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	reason := fmt.Sprintf("sfc:%s", req.Name)
	if err := r.handleControllerEvent(ctx, reason); err != nil {
		return ctrl.Result{}, err
	}
	r.epTrigger.TriggerWithReason(reason)
	return ctrl.Result{}, nil
}

func (r *ServiceSteeringReconciler) handleControllerEvent(ctx context.Context, reason string) (err_ error) {
	reconcileLock.Lock()
	defer reconcileLock.Unlock()

	log := sfclog.WithField("reason", reason)
	start := time.Now()
	log.Debug("Reconciling")
	defer func() { log.Debugf("Finished reconciling in %s", time.Since(start)) }()

	defer func() {
		outcome := labelValueOutcomeSuccess
		if err_ != nil {
			log.Error(err_)
			outcome = labelValueOutcomeFail
		}
		r.metrics.ReconcileTotal.WithLabelValues(reconcileTypeController, outcome).Inc()
	}()

	if err := r.updateSelectorCache(ctx, log); err != nil {
		err_ = fmt.Errorf("failed to update TrafficSelector cache: %v", err)
		return
	}
	if err := r.reconcilePathMap(ctx, log); err != nil {
		err_ = fmt.Errorf("failed to reconcile SFC path map: %v", err)
		return
	}
	if err := r.reconcileDataPathEnablement(ctx, log); err != nil {
		err_ = fmt.Errorf("failed to adjust data path enablement: %v", err)
		return
	}
	return
}

// Only reconcile the selector maps for endpoint events
func (r *ServiceSteeringReconciler) handleTriggerEvent(reasons []string) {
	reconcileLock.Lock()
	defer reconcileLock.Unlock()

	ctx := context.Background()
	log := sfclog.WithField("reasons", reasons)
	start := time.Now()
	log.Info("Reconciling")
	defer func() { log.Debugf("Finished reconciling in %s", time.Since(start)) }()

	outcome := labelValueOutcomeSuccess
	defer func() {
		r.metrics.ReconcileTotal.WithLabelValues(reconcileTypeTrigger, outcome).Inc()
	}()

	if err := r.reconcileSelectorMaps(ctx, log); err != nil {
		log.WithError(err).Error("Failed to reconcile SFC selector maps")
		outcome = labelValueOutcomeFail
		return
	}
}

func (r *ServiceSteeringReconciler) reconcilePathMap(ctx context.Context, log *logrus.Entry) error {
	desiredPaths := r.desiredPaths()
	existingPaths, err := existingPaths()
	if err != nil {
		return fmt.Errorf("unable to dump google_sfc_path map: %v", err)
	}

	for key := range existingPaths {
		if _, ok := desiredPaths[key]; !ok {
			// Path is not needed, delete it
			deleted, err := sfc.PathMap.SilentDelete(&key)
			if err != nil {
				return fmt.Errorf("unable to delete path %s: %v", &key, err)
			}
			if deleted {
				log.Infof("Deleted path %s", &key)
			}
		}
	}
	for key, entry := range desiredPaths {
		if err := sfc.PathMap.Update(&key, &entry); err != nil {
			return fmt.Errorf("unable to update path %s: %v", &key, err)
		}
		log.Infof("Updated path, %s: %s", &key, &entry)
	}
	return nil
}

func (r *ServiceSteeringReconciler) reconcileSelectorMaps(ctx context.Context, log *logrus.Entry) error {
	desiredSelectors := r.desiredSelectors(log)
	existingSelectors, err := existingSelectors()
	if err != nil {
		return fmt.Errorf("unable to dump google_sfc_select map: %v", err)
	}

	for key := range existingSelectors {
		if _, ok := desiredSelectors[key]; !ok {
			// selector is not needed, delete it
			deleted, err := sfc.SelectMap.SilentDelete(&key)
			if err != nil {
				return fmt.Errorf("unable to delete selector %s: %v", &key, err)
			}
			if deleted {
				log.Infof("Deleted selector %s", &key)
			}
		}
	}
	for key, entry := range desiredSelectors {
		if err := sfc.SelectMap.Update(&key, &entry); err != nil {
			return fmt.Errorf("unable to update selector %s: %v", &key, err)
		}
		log.Infof("Updated selector: %s", &key)
	}

	return nil
}

func (r *ServiceSteeringReconciler) desiredPaths() map[sfc.PathKey]sfc.PathEntry {
	desiredPaths := make(map[sfc.PathKey]sfc.PathEntry)
	for _, ts := range r.selectorCache {
		path := ts.entry.PathKey()
		desiredPaths[path] = *sfc.NewPathEntry(ts.serviceIP)
	}
	return desiredPaths
}

func (r *ServiceSteeringReconciler) desiredSelectors(log *logrus.Entry) map[sfc.SelectKey]sfc.SelectEntry {
	desiredSelectors := make(map[sfc.SelectKey]sfc.SelectEntry)
	if len(r.selectorCache) == 0 {
		return desiredSelectors
	}
	numEndpointsSelected := 0
	for _, ep := range r.EpManager.GetEndpoints() {
		if ep.IsHost() {
			continue
		}
		// TODO(optimize): Use a cache for pods with the same labels
		epDesiredSelectors := r.desiredEpSelectors(log, ep)
		for k, v := range epDesiredSelectors {
			desiredSelectors[k] = v
		}
		if len(epDesiredSelectors) > 0 {
			numEndpointsSelected++
		}
	}
	r.metrics.Endpoints.Set(float64(numEndpointsSelected))
	return desiredSelectors
}

func (r *ServiceSteeringReconciler) getEPLabels(ep *endpoint.Endpoint) (map[string]string, error) {
	pName := &slim_corev1.Pod{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:      ep.K8sPodName,
			Namespace: ep.K8sNamespace,
		},
	}
	pod, exists, err := r.podStore.Get(pName)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch pod %s/%s in store: %v", ep.K8sNamespace, ep.K8sPodName, err)
	}
	if !exists {
		return nil, fmt.Errorf("pod %s/%s not found in store", ep.K8sNamespace, ep.K8sPodName)
	}

	nsName := &slim_corev1.Namespace{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name: ep.K8sNamespace,
		},
	}
	ns, exists, err := r.namespaceStore.Get(nsName)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch namespace %s in store: %v", ep.K8sNamespace, err)
	}
	if !exists {
		return nil, fmt.Errorf("namespace %s not found in store", ep.K8sNamespace)
	}

	labels := map[string]string{}
	for k, v := range ns.GetLabels() {
		labels[policy.JoinPath(ciliumio.PodNamespaceMetaLabels, k)] = v
	}
	for k, v := range pod.GetLabels() {
		labels[k] = v
	}
	return labels, nil
}

func (r *ServiceSteeringReconciler) desiredEpSelectors(log *logrus.Entry, ep *endpoint.Endpoint) map[sfc.SelectKey]sfc.SelectEntry {
	if ep.GetPod() == nil {
		return nil
	}
	epId := ep.GetID16()
	log = log.WithFields(logrus.Fields{
		"endpoint": epId,
		"pod":      ep.GetK8sPodName(),
	})

	labels, err := r.getEPLabels(ep)
	if err != nil {
		log.WithError(err).Warningf("skipped pod because failed to get labels")
		return nil
	}

	desiredSelectors := make(map[sfc.SelectKey]sfc.SelectEntry)
	for i := range r.selectorCache {
		selector := &r.selectorCache[i]
		log := log.WithField("selector", selector.Name)
		if networkMatches := selector.networkID == ep.GetNetworkID(); !networkMatches {
			log.Debug("Network does not match")
			continue
		}
		if err := selector.matchesLabels(labels); err != nil {
			log.Debugf("Pod is not subject to TrafficSelector: %v", err)
			continue
		}
		log.Debug("Pod is subject to TrafficSelector")
		egress := selector.Spec.Egress != nil
		for p := range selector.portSelectors {
			selectorKey := sfc.NewSelectKey(epId, egress, p.portNumber, p.proto, selector.cidr)
			desiredSelectors[*selectorKey] = selector.entry
		}
	}
	return desiredSelectors
}

// Extract, pre-process, and cache TrafficSelectors so they're easier to work with
func (r *ServiceSteeringReconciler) updateSelectorCache(ctx context.Context, log *logrus.Entry) error {
	var selectorList v1.TrafficSelectorList
	if err := r.List(ctx, &selectorList); err != nil {
		return fmt.Errorf("unable to list TrafficSelectors: %v", err)
	}
	selectors := []extractedSelector{}
	for i := range selectorList.Items {
		ts := &selectorList.Items[i]
		log := log.WithField("selector", ts.Name)

		selector, err := newExtractedSelector(ts)
		if err != nil {
			log.WithError(err).Warnf("Unable to extract TrafficSelector fields")
			continue
		}
		if err := r.extractSFC(ctx, log, selector); err != nil {
			log.WithError(err).Debugf("Unable to extract SFC")
			continue
		}
		if err := r.extractNetwork(ctx, selector); err != nil {
			log.WithError(err).Warnf("Unable to extract network")
			continue
		}
		selectors = append(selectors, *selector)
	}
	r.selectorCache = selectors
	return nil
}

// Extract associated SFC's SPI and service IP
func (r *ServiceSteeringReconciler) extractSFC(ctx context.Context, log *logrus.Entry, selector *extractedSelector) error {
	sfcName := selector.Spec.ServiceFunctionChain
	var chain v1.ServiceFunctionChain
	if err := r.Get(ctx, types.NamespacedName{Name: sfcName}, &chain); err != nil {
		return err
	}

	if chain.Status.ServicePathId == nil {
		return fmt.Errorf("unassigned SPI")
	}
	spi := *chain.Status.ServicePathId
	entry, err := sfc.NewSelectEntry(uint32(spi), 1, selector.cidr)
	if err != nil {
		return err
	}

	if len(chain.Spec.ServiceFunctions) == 0 {
		return fmt.Errorf("SFC %s has no service functions", chain.Name)
	}
	if len(chain.Spec.ServiceFunctions) > 1 {
		return fmt.Errorf("SFC %s has >1 SFs, which is not supported", chain.Name)
	}
	sf := chain.Spec.ServiceFunctions[0]
	svcName := v1.ServiceName(sf.Name, chain.UID)
	var svc corev1.Service
	if err := r.Get(ctx, types.NamespacedName{Name: svcName, Namespace: sf.Namespace}, &svc); err != nil {
		return fmt.Errorf("unable to get Service %q: %v", sfcName, err)
	}
	ip := svc.Spec.ClusterIP
	if ip == "" || ip == corev1.ClusterIPNone {
		return fmt.Errorf("service %s has no ClusterIP", svc.Name)
	}

	selector.entry = *entry
	selector.serviceIP = net.ParseIP(ip)
	return nil
}

// Extract network id, returning 0 for default/unspecified network
func (r *ServiceSteeringReconciler) extractNetwork(ctx context.Context, selector *extractedSelector) error {
	networkName := selector.Spec.Subject.Network
	if len(networkName) == 0 || networkName == networkv1.DefaultPodNetworkName {
		selector.networkID = 0
		return nil
	}
	var network networkv1.Network
	if err := r.Get(ctx, types.NamespacedName{Name: networkName}, &network); err != nil {
		return fmt.Errorf("unable to get Network %q: %v", networkName, err)
	}
	selector.networkID = connector.GenerateNetworkIDFromUID(network.UID)
	return nil
}

func (r *ServiceSteeringReconciler) reconcileDataPathEnablement(ctx context.Context, log *logrus.Entry) error {
	shouldEnable := !isPathMapEmpty()

	if shouldEnable {
		if err := addGeneveDev(geneveDevName, log); err != nil {
			return err
		}
	} else {
		if err := removeDevice(geneveDevName, log); err != nil {
			return err
		}
	}

	existing := option.Config.Opts.IsEnabled(option.GoogleServiceSteeringDataPath)
	if shouldEnable == existing {
		log.Debugf("Service steering data path is already %s.", optString(existing))
		return nil
	}
	cfg := models.DaemonConfigurationSpec{
		Options: models.ConfigurationMap{
			option.GoogleServiceSteeringDataPath: optString(shouldEnable),
		},
	}
	log.Infof("Patching config to set %s to %s", option.GoogleServiceSteeringDataPath, optString(shouldEnable))
	if err := r.cp.ConfigPatch(cfg); err != nil {
		return fmt.Errorf("unable to change configuration: %s", err)
	}
	log.Infof("Set %s to %s", option.GoogleServiceSteeringDataPath, optString(shouldEnable))
	return nil
}

func optString(enable bool) string {
	if enable {
		return "Enabled"
	}
	return "Disabled"
}
