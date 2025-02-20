package pip

import (
	"context"
	"fmt"
	"net"

	networkv1 "github.com/GoogleCloudPlatform/gke-networking-api/apis/network/v1"
	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/datapath/connector"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/maps/pip"
	"github.com/cilium/cilium/pkg/metrics"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/time"
	"github.com/cilium/cilium/pkg/trigger"
	"github.com/sirupsen/logrus"
	pipv1 "gke-internal.googlesource.com/anthos-networking/apis/v2/persistent-ip/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
)

var (
	minTriggerInternal = time.Second * 2
	pipMetricTracker   = make(map[pipMetricKey]int)
)

type gkeIPRoutePod struct {
	namespace string
	podName   string
	networkID uint32
}

type pipMetricKey struct {
	family  string
	network string
}

// GKEIPRouteReconciler reconciles GKEIPRoute objects.
type GKEIPRouteReconciler struct {
	client.Client
	em        endpointmanager.EndpointManager
	epTrigger *trigger.Trigger
	Log       *logrus.Entry
	// protects access to gkeIPRoutePods
	reconcileLock lock.Mutex
	// denotes a map of pods along with the network that
	// any GKEIPRoute is referenced to.
	gkeIPRoutePodsCache   map[gkeIPRoutePod]bool
	googleMultiNICEnabled bool
}

func (r *GKEIPRouteReconciler) Reconcile(ctx context.Context, req ctrl.Request) (_ ctrl.Result, rerr error) {
	return r.handleReconcile(ctx, "gkeiproute: "+req.String())
}

func (r *GKEIPRouteReconciler) handleReconcile(ctx context.Context, reconcileSource string) (_ ctrl.Result, rerr error) {
	r.Log.Infof("reconcile trigger source: %s, reconciling", reconcileSource)
	gkeIPRouteList := &pipv1.GKEIPRouteList{}
	if err := r.List(ctx, gkeIPRouteList); err != nil {
		r.Log.WithError(err).Error("Unable to list GKEIPRoute objects")
		return ctrl.Result{}, err
	}
	updatedGKEIPRoutes, reconcileErr := r.reconcileRoutingMap(ctx, gkeIPRouteList.Items)
	updatePIPMetrics()

	var updateErr error
	requeue := false
	for _, gkeIPRoute := range updatedGKEIPRoutes {
		r.Log.Infof("updating GKEIPRoute %s with DPV2Ready condition %t", gkeIPRoute.Name, meta.IsStatusConditionTrue(gkeIPRoute.Status.Conditions, string(pipv1.IPRouteDPV2Ready)))
		if err := r.Status().Update(ctx, gkeIPRoute); err != nil {
			if k8sErrors.IsConflict(err) {
				r.Log.Infof("conflict while patching GKEIPRoute %s conditions, requeuing", gkeIPRoute.Name)
				requeue = true
			} else {
				r.Log.WithError(err).Errorf("Failure while patching GKEIPRoute %s conditions", gkeIPRoute.Name)
				updateErr = err
			}
		}
	}
	if reconcileErr != nil {
		return ctrl.Result{}, reconcileErr
	}
	return ctrl.Result{Requeue: requeue}, updateErr
}

func (r *GKEIPRouteReconciler) selectedPods(ctx context.Context, ipr *pipv1.GKEIPRoute) ([]string, error) {
	if !isLoadBalancing(ipr) {
		return ipr.Status.Pods, nil
	}
	epsList := &discoveryv1.EndpointSliceList{}
	if err := r.List(ctx, epsList, client.MatchingLabelsSelector{
		Selector: labels.SelectorFromSet(map[string]string{pipv1.GKEIPRouteKey: ipr.Name}),
	}, client.InNamespace(ipr.Namespace)); err != nil {
		return nil, fmt.Errorf("unable to list endpoint slices: %v", err)
	}
	pods := []string{}
	for _, eps := range epsList.Items {
		for _, ep := range eps.Endpoints {
			if ep.NodeName == nil || *ep.NodeName != nodeTypes.GetName() {
				continue
			}
			if ep.TargetRef == nil || ep.TargetRef.Name == "" {
				r.Log.Warningf("Found empty target ref in EndpointSlice %q. Skipped the endpoint", eps.Name)
				continue
			}
			pods = append(pods, ep.TargetRef.Name)
		}
	}
	return pods, nil
}

func (r *GKEIPRouteReconciler) reconcileRoutingMap(ctx context.Context, gkeIPRoutes []pipv1.GKEIPRoute) (updatedGKEIPRoutes []*pipv1.GKEIPRoute, err error) {
	// map of gkeIPRoutes that are accepted with the latest
	// generation of GKEIPRoute spec
	acceptedGKEIPRoutes := map[string]*pipv1.GKEIPRoute{}
	for i, gkeIPRoute := range gkeIPRoutes {
		r.Log.Debugf("listed gkeIPRoute: %s", gkeIPRoute.GetName())
		accepted := meta.FindStatusCondition(gkeIPRoute.Status.Conditions, string(pipv1.IPRouteAccepted))
		if accepted != nil && accepted.Status == metav1.ConditionTrue && accepted.ObservedGeneration == gkeIPRoute.Generation {
			_, nwType, err := r.networkInfo(ctx, *gkeIPRoute.Spec.Network)
			if err != nil {
				return nil, fmt.Errorf("failed to obtain network information from gkeIPRoute %s: %v", gkeIPRoute.Name, err)
			}
			if nwType == networkv1.DeviceNetworkType {
				// no additional datapath configuration required for device type networks
				updatedGKEIPRoute := r.processDeviceTypeNetworkGKEIPRoutes(ctx, &gkeIPRoute)
				if updatedGKEIPRoute != nil {
					updatedGKEIPRoutes = append(updatedGKEIPRoutes, updatedGKEIPRoute)
				}
				continue
			}
			acceptedGKEIPRoutes[gkeIPRoute.Namespace+"/"+gkeIPRoute.Name] = &gkeIPRoutes[i]
		}
	}

	desiredEntries, err := r.desiredRoutingEntries(ctx, acceptedGKEIPRoutes)
	if err != nil {
		return nil, fmt.Errorf("unable to compute the desired persistent ip routing map entries: %v", err)
	}
	existingEntries, err := existingRoutingEntries()
	if err != nil {
		return nil, fmt.Errorf("unable to fetch existing persistent ip routing map entries: %v", err)
	}
	// remove outdated entries from existingEntries, can ignore any errors
	// as deletion failures are not critical.
	for key := range existingEntries {
		r.Log.Debugf("existing bpf entry: %s", key.String())
		if _, ok := desiredEntries[key]; !ok {
			r.Log.Infof("deleting bpf entry: %s", key.String())
			_, err := pip.RoutingMap.SilentDelete(&key)
			if err != nil {
				r.Log.WithError(err).Warnf("could not delete outdated routing record: %v", key)
			}
		}
	}
	shouldRequeue := false
	// update map with desired entries, update DPV2Ready condition of GKEIPRoute accordingly
	for key, pipEntry := range desiredEntries {
		ipr := pipEntry.gkeIPRoute
		if err := pip.RoutingMap.Update(&key, &pipEntry.value); err != nil {
			if !isLoadBalancing(ipr) {
				meta.SetStatusCondition(&ipr.Status.Conditions, metav1.Condition{
					Type:               string(pipv1.IPRouteDPV2Ready),
					Status:             metav1.ConditionFalse,
					Reason:             string(pipv1.DPV2NotReady),
					Message:            err.Error(),
					ObservedGeneration: ipr.GetObjectMeta().GetGeneration(),
				})
			}
			r.Log.WithError(err).Warnf("error in updating routing entry for gkeIPRoute: %s", pipEntry.gkeIPRoute.Name)
			shouldRequeue = true
		} else {
			r.Log.Infof("Updated routing entry, %s: %s", &key, &pipEntry.value)
			if !isLoadBalancing(ipr) {
				meta.SetStatusCondition(&ipr.Status.Conditions, metav1.Condition{
					Type:               string(pipv1.IPRouteDPV2Ready),
					Status:             metav1.ConditionTrue,
					Reason:             string(pipv1.IPRouteDPV2Ready),
					ObservedGeneration: ipr.GetObjectMeta().GetGeneration(),
				})
			}
			pipMetricTracker[pipMetricKey{string(key.Family), *ipr.Spec.Network}] += 1
		}
		// only update those GKEIPRoutes that have a change in the DPV2Ready condition
		if r.needsUpdate(ipr, acceptedGKEIPRoutes[ipr.Namespace+"/"+ipr.Name]) {
			updatedGKEIPRoutes = append(updatedGKEIPRoutes, ipr)
		}
	}
	if shouldRequeue {
		return updatedGKEIPRoutes, fmt.Errorf("could not update map entries for one or more GKEIPRoutes")
	}
	return updatedGKEIPRoutes, nil
}

type pipEntry struct {
	value      pip.RoutingEntry
	gkeIPRoute *pipv1.GKEIPRoute
}

func isLoadBalancing(ipr *pipv1.GKEIPRoute) bool {
	return ipr.Spec.LoadBalancing != nil
}

// desiredRoutingEntries returns the desired bpf endpoints map state.
func (r *GKEIPRouteReconciler) desiredRoutingEntries(ctx context.Context, gkeIPRoutes map[string]*pipv1.GKEIPRoute) (map[pip.CIDRKey]pipEntry, error) {
	r.reconcileLock.Lock()
	defer r.reconcileLock.Unlock()
	desiredMap := map[pip.CIDRKey]pipEntry{}
	r.gkeIPRoutePodsCache = map[gkeIPRoutePod]bool{}
	for _, gkeIPRoute := range gkeIPRoutes {
		r.Log.Debugf("accepted gkeIPRoute: %s/%s", gkeIPRoute.GetNamespace(), gkeIPRoute.GetName())
		// compute networkID
		nwID, _, err := r.networkInfo(ctx, *gkeIPRoute.Spec.Network)
		if err != nil {
			return nil, fmt.Errorf("error while computing networkID of gkeiproute %s", gkeIPRoute.Name)
		}
		iprPods := []*gkeIPRoutePod{}
		if !isLoadBalancing(gkeIPRoute) {
			// only support gkeiproutes with 1 matching pod
			if len(gkeIPRoute.Status.Pods) != 1 {
				r.Log.Infof("gkeiproute %s/%s must have only one pod, current len=%d, ignoring", gkeIPRoute.Namespace, gkeIPRoute.Name, len(gkeIPRoute.Status.Pods))
				continue
			}
			iprPods = append(iprPods, &gkeIPRoutePod{
				namespace: gkeIPRoute.Namespace,
				podName:   gkeIPRoute.Status.Pods[0],
				networkID: nwID,
			})
		} else {
			pods, err := r.selectedPods(ctx, gkeIPRoute)
			if err != nil {
				return nil, err
			}
			if len(pods) > 0 {
				r.Log.Infof("Load balancing GKEIPRoute %s/%s is selecting pods %v", gkeIPRoute.Namespace, gkeIPRoute.Name, pods)
			}
			for _, pod := range pods {
				iprPods = append(iprPods, &gkeIPRoutePod{
					namespace: gkeIPRoute.Namespace,
					podName:   pod,
					networkID: nwID,
				})
			}
		}
		for _, iprPod := range iprPods {
			r.gkeIPRoutePodsCache[*iprPod] = true
			// ignore endpoints that are not on the current node or do not belong to the GKEIPRoute's network.
			var ep *endpoint.Endpoint
			podName := fmt.Sprintf("%s/%s", iprPod.namespace, iprPod.podName)
			if ep = r.LookupEndpointByPodNameAndNetwork(podName, iprPod.networkID); ep == nil {
				continue
			}
			r.Log.Infof("Found local endpoint %d of pod %s for GKEIPRoute %s", ep.ID, podName, gkeIPRoute.Name)
			// create map entries for each of the IP CIDRs
			// pointing to the pod endpoint
			for _, address := range gkeIPRoute.Spec.Addresses {
				_, ipNet, err := net.ParseCIDR(address.Value)
				if err != nil {
					return nil, fmt.Errorf("error while parsing GKEIPRoute %s address %s", gkeIPRoute.Name, address.Value)
				}
				r.Log.Debugf("bpf map entry for %s, entry: %s", gkeIPRoute.GetName(), address.Value)
				cidrKey := pip.NewCIDRKey(ipNet)
				eip := net.ParseIP(ep.GetIPv4Address())
				if eip == nil {
					return nil, fmt.Errorf("error parsing endpoint %d address %s", ep.ID, ep.GetIPv4Address())
				}
				routingEntry := pip.NewRoutingEntry(net.ParseIP(ep.GetIPv4Address()))
				gkeIPRouteEntry := pipEntry{value: *routingEntry, gkeIPRoute: gkeIPRoute.DeepCopy()}
				desiredMap[*cidrKey] = gkeIPRouteEntry
			}
		}
	}
	return desiredMap, nil
}

// processDeviceTypeNetworkGKEIPRoutes sets DPV2Ready condition to true for accepted GKEIPRoutes with a matching pod defined on a device-typed network because no additional datapath configuration is required.
func (r *GKEIPRouteReconciler) processDeviceTypeNetworkGKEIPRoutes(ctx context.Context, gkeIPRoute *pipv1.GKEIPRoute) *pipv1.GKEIPRoute {
	if isLoadBalancing(gkeIPRoute) {
		// For load balancing, we don't update dpv2 ready status
		return nil
	}
	if len(gkeIPRoute.Status.Pods) != 1 {
		r.Log.Infof("gkeiproute %s/%s must have only one pod, current len=%d, ignoring", gkeIPRoute.Namespace, gkeIPRoute.Name, len(gkeIPRoute.Status.Pods))
		return nil
	}
	iprCopy := gkeIPRoute.DeepCopy()
	meta.SetStatusCondition(&iprCopy.Status.Conditions, metav1.Condition{
		Type:               string(pipv1.IPRouteDPV2Ready),
		Status:             metav1.ConditionTrue,
		Reason:             string(pipv1.IPRouteDPV2Ready),
		ObservedGeneration: iprCopy.GetObjectMeta().GetGeneration(),
	})
	// only update those GKEIPRoutes that have a change in the DPV2Ready condition
	if r.needsUpdate(iprCopy, gkeIPRoute) {
		return iprCopy
	}
	return nil
}

func (r *GKEIPRouteReconciler) handleEndpointTriggerEvent(reasons []string) {
	// trigger an GKEIPRoute reconcile on every endpoint that passed the checks in EndpointCreated handler
	// on this node. The reconcile will always respect the pods that are currently in the GKEIPRoute status.
	// This trigger helps in solving cases where the reconciler is triggered *before* the endpoint is
	// reflected in local endpoint manager.
	if _, err := r.handleReconcile(context.TODO(), reasons[0]); err != nil {
		r.Log.Errorf("failed to reconcile routing maps while handling endpoint trigger: %s", err.Error())
	}
}

func (r *GKEIPRouteReconciler) EndpointCreated(ep *endpoint.Endpoint) {
	pod := ep.GetPod()
	if pod == nil {
		// There is chance that pod Object is not filled during endpoint creation.
		// TODO(b/310746914): We will miss the trigger because of this.
		r.Log.Infof("skipping endpoint %d due to nil pod", ep.GetID16())
		return
	}
	ann := pod.GetAnnotations()
	_, ok := ann[networkv1.InterfaceAnnotationKey]
	if !ok {
		return
	}
	reason := fmt.Sprintf("ep:%d, namespace:%s, pod:%s", ep.GetID16(), ep.GetK8sNamespace(), ep.GetK8sPodName())
	iprPod := gkeIPRoutePod{
		namespace: ep.K8sNamespace,
		podName:   ep.K8sPodName,
		networkID: ep.GetNetworkID(),
	}
	if !r.isGKEIPRouteEndpoint(iprPod) {
		return
	}
	r.Log.Infof("endpoint passed trigger checks, triggering reconcile for %s", reason)
	r.epTrigger.TriggerWithReason(reason)
}

func (r *GKEIPRouteReconciler) EndpointDeleted(ep *endpoint.Endpoint, conf endpoint.DeleteConfig) {}

func (r *GKEIPRouteReconciler) EndpointRestored(ep *endpoint.Endpoint) {}

// SetupWithManager configures this controller in the manager.
func (r *GKEIPRouteReconciler) SetupWithManager(mgr ctrl.Manager) error {
	// Use a trigger function for endpoint updates.
	rt, err := trigger.NewTrigger(trigger.Parameters{
		Name:        "persistent-ip-endpoint-trigger",
		MinInterval: minTriggerInternal,
		TriggerFunc: r.handleEndpointTriggerEvent,
	})
	if err != nil {
		return fmt.Errorf("unable to initialize persistent-ip endpoint trigger function: %v", err)
	}
	r.epTrigger = rt
	// Only subscribe to endpoint manager when manager is started
	mgr.Add(manager.RunnableFunc(func(context.Context) error {
		r.em.Subscribe(r)
		return nil
	}))
	return ctrl.NewControllerManagedBy(mgr).
		For(&pipv1.GKEIPRoute{}).
		Owns(&discoveryv1.EndpointSlice{}, builder.WithPredicates(predicate.NewPredicateFuncs(func(obj client.Object) bool {
			r.Log.Infof("Triggering reconciling by EndpointSlice: %s/%s", obj.GetNamespace(), obj.GetName())
			return true
		}))).
		Complete(r)
}

// LookupEndpointByPodNameAndNetwork looks up endpoint in a pod by namespace + pod name and a network id.
func (r *GKEIPRouteReconciler) LookupEndpointByPodNameAndNetwork(name string, networkID uint32) *endpoint.Endpoint {
	// don't support queuries when multinic is disabled and networkID is non-zero
	if !r.googleMultiNICEnabled && networkID != 0 {
		return nil
	}
	eps := r.em.GetEndpointsByPodName(name)
	for _, ep := range eps {
		if ep.GetNetworkID() == networkID {
			return ep
		}
	}
	return nil
}

func (r *GKEIPRouteReconciler) networkInfo(ctx context.Context, networkName string) (uint32, networkv1.NetworkType, error) {
	if networkv1.IsDefaultNetwork(networkName) {
		return 0, networkv1.L3NetworkType, nil
	}
	var network networkv1.Network
	if err := r.Get(ctx, types.NamespacedName{Name: networkName}, &network); err != nil {
		return 0, "", err
	}

	return connector.GenerateNetworkID(&network), network.Spec.Type, nil
}

func (r *GKEIPRouteReconciler) isGKEIPRouteEndpoint(key gkeIPRoutePod) bool {
	r.reconcileLock.Lock()
	defer r.reconcileLock.Unlock()
	if _, ok := r.gkeIPRoutePodsCache[key]; ok {
		return true
	}
	return false
}

func (r *GKEIPRouteReconciler) needsUpdate(gkeIPRoute1, gkeIPRoute2 *pipv1.GKEIPRoute) bool {
	dpv2Ready1 := meta.FindStatusCondition(gkeIPRoute1.Status.Conditions, string(pipv1.IPRouteDPV2Ready))
	dpv2Ready2 := meta.FindStatusCondition(gkeIPRoute2.Status.Conditions, string(pipv1.IPRouteDPV2Ready))
	if dpv2Ready1 == nil && dpv2Ready2 == nil {
		return false
	}
	if dpv2Ready1 == nil || dpv2Ready2 == nil {
		return true
	}
	if dpv2Ready1.ObservedGeneration != dpv2Ready2.ObservedGeneration {
		return true
	}
	if dpv2Ready1.Status != dpv2Ready2.Status {
		return true
	}
	if dpv2Ready1.Message != dpv2Ready2.Message {
		return true
	}
	return false
}

func existingRoutingEntries() (map[pip.CIDRKey]pip.RoutingEntry, error) {
	dump := make(map[pip.CIDRKey]pip.RoutingEntry)
	cb := func(k bpf.MapKey, v bpf.MapValue) {
		key := k.(*pip.CIDRKey).DeepCopy()
		value := v.(*pip.RoutingEntry).DeepCopy()
		dump[*key] = *value
	}
	stats := bpf.NewDumpStats(pip.RoutingMap)
	err := pip.RoutingMap.DumpReliablyWithCallback(cb, stats)
	if err != nil {
		return nil, err
	}
	return dump, nil
}

func updatePIPMetrics() {
	// Set metrics values, delete entry if count is 0
	for key, count := range pipMetricTracker {
		if count == 0 {
			metrics.PersistentIPEndpointsTotal.DeleteLabelValues(key.family, key.network)
			delete(pipMetricTracker, key)
			continue
		}
		metrics.PersistentIPEndpointsTotal.WithLabelValues(key.family, key.network).Set(float64(count))
		// Set to 0 so entry is deleted if it's not updated in the next iteration
		pipMetricTracker[key] = 0
	}
}
