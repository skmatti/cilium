package pip

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/datapath/connector"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/maps/pip"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/trigger"
	"github.com/sirupsen/logrus"
	pipv1 "gke-internal.googlesource.com/anthos-networking/apis/v2/persistent-ip/v1"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	networkv1 "k8s.io/cloud-provider-gcp/crd/apis/network/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
)

var (
	ipv4Mask           = net.CIDRMask(32, 8*net.IPv4len)
	minTriggerInternal = time.Second * 2
)

type gkeIPRoutePod struct {
	namespace string
	podName   string
	networkID uint32
}

// GKEIPRouteReconciler reconciles GKEIPRoute objects.
type GKEIPRouteReconciler struct {
	client.Client
	*endpointmanager.EndpointManager
	epTrigger *trigger.Trigger
	Log       *logrus.Entry
	// protects access to gkeIPRoutePods
	reconcileLock lock.Mutex
	// denotes a map of pods along with the network that
	// any GKEIPRoute is referenced to.
	gkeIPRoutePodsCache map[gkeIPRoutePod]bool
}

func (r *GKEIPRouteReconciler) Reconcile(ctx context.Context, req ctrl.Request) (_ ctrl.Result, rerr error) {
	return r.handleReconcile(ctx, "gkeiproute: "+req.Name)
}

func (r *GKEIPRouteReconciler) handleReconcile(ctx context.Context, reconcileSource string) (_ ctrl.Result, rerr error) {
	r.Log.Infof("reconcile trigger source: %s, reconciling", reconcileSource)
	gkeIPRouteList := &pipv1.GKEIPRouteList{}
	if err := r.List(ctx, gkeIPRouteList); err != nil {
		r.Log.WithError(err).Error("Unable to list GKEIPRoute objects")
		return ctrl.Result{}, err
	}
	updatedGKEIPRoutes, reconcileErr := r.reconcileRoutingMap(ctx, gkeIPRouteList.Items)

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

func (r *GKEIPRouteReconciler) reconcileRoutingMap(ctx context.Context, gkeIPRoutes []pipv1.GKEIPRoute) (updatedGKEIPRoutes []*pipv1.GKEIPRoute, err error) {
	// map of gkeIPRoutes that are accepted with latest
	// generation of GKEIPRoute spec
	acceptedGKEIPRoutes := map[string]*pipv1.GKEIPRoute{}
	for _, gkeIPRoute := range gkeIPRoutes {
		accepted := meta.FindStatusCondition(gkeIPRoute.Status.Conditions, string(pipv1.IPRouteAccepted))
		if accepted != nil && accepted.Status == metav1.ConditionTrue && accepted.ObservedGeneration == gkeIPRoute.Generation {
			acceptedGKEIPRoutes[gkeIPRoute.Name] = &gkeIPRoute
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
		if _, ok := desiredEntries[key]; !ok {
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
			meta.SetStatusCondition(&ipr.Status.Conditions, metav1.Condition{
				Type:               string(pipv1.IPRouteDPV2Ready),
				Status:             metav1.ConditionFalse,
				Reason:             string(pipv1.DPV2NotReady),
				Message:            err.Error(),
				ObservedGeneration: ipr.GetObjectMeta().GetGeneration(),
			})
			r.Log.WithError(err).Warnf("error in updating routing entry for gkeIPRoute: %s", pipEntry.gkeIPRoute.Name)
			shouldRequeue = true
		} else {
			meta.SetStatusCondition(&ipr.Status.Conditions, metav1.Condition{
				Type:               string(pipv1.IPRouteDPV2Ready),
				Status:             metav1.ConditionTrue,
				Reason:             string(pipv1.IPRouteDPV2Ready),
				ObservedGeneration: ipr.GetObjectMeta().GetGeneration(),
			})
		}
		// only update those GKEIPRoutes that have a change in the DPV2Ready condition
		if r.needsUpdate(ipr, acceptedGKEIPRoutes[ipr.Name]) {
			updatedGKEIPRoutes = append(updatedGKEIPRoutes, ipr)
		}
		r.Log.Infof("Updated routing entry, %s: %s", &key, &pipEntry.value)
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

// desiredRoutingEntries returns the desired map state along with a list of gkeiproutes whose pod's corresponding
// endpoints do not exist yet.
func (r *GKEIPRouteReconciler) desiredRoutingEntries(ctx context.Context, gkeIPRoutes map[string]*pipv1.GKEIPRoute) (map[pip.CIDRKey]pipEntry, error) {
	r.reconcileLock.Lock()
	defer r.reconcileLock.Unlock()
	desiredMap := map[pip.CIDRKey]pipEntry{}
	r.gkeIPRoutePodsCache = map[gkeIPRoutePod]bool{}
	for _, gkeIPRoute := range gkeIPRoutes {
		// only support gkeiproutes with 1 matching pod
		if len(gkeIPRoute.Status.Pods) != 1 {
			r.Log.Infof("gkeiproute %s must have only one pod, current len=%d, ignoring", gkeIPRoute.Name, len(gkeIPRoute.Status.Pods))
			continue
		}
		// compute networkID
		nwID, err := r.networkID(ctx, *gkeIPRoute.Spec.Network)
		if err != nil {
			return nil, fmt.Errorf("error while computing networkID of gkeiproute %s", gkeIPRoute.Name)
		}
		// populate GKEIPRoutePods cache with the namespace, pod and network details
		iprPod := gkeIPRoutePod{
			namespace: gkeIPRoute.Namespace,
			podName:   gkeIPRoute.Status.Pods[0],
			networkID: nwID,
		}
		r.gkeIPRoutePodsCache[iprPod] = true
		// ignore endpoints that are not on the current node or do not belong to the GKEIPRoute's network.
		var ep *endpoint.Endpoint
		podName := fmt.Sprintf("%s/%s", gkeIPRoute.Namespace, gkeIPRoute.Status.Pods[0])
		if ep = r.LookupEndpointByPodNameAndNetwork(podName, nwID); ep == nil {
			continue
		}
		// create map entries for each of the IP CIDRs
		// pointing to the pod endpoint
		for _, address := range gkeIPRoute.Spec.Addresses {
			ip := net.ParseIP(address.Value)
			cidrKey := pip.NewCIDRKey(&net.IPNet{
				IP:   ip,
				Mask: ipv4Mask,
			})
			routingEntry := pip.NewRoutingEntry(net.ParseIP(ep.GetIPv4Address()))
			gkeIPRouteEntry := pipEntry{value: *routingEntry, gkeIPRoute: gkeIPRoute.DeepCopy()}
			desiredMap[*cidrKey] = gkeIPRouteEntry
		}
	}
	return desiredMap, nil
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
	// TODO(b/292558915) - Remove this check when persistent IP is supported on default network.
	if !ok || !ep.IsMultiNIC() {
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
		r.EndpointManager.Subscribe(r)
		return nil
	}))
	return ctrl.NewControllerManagedBy(mgr).
		For(&pipv1.GKEIPRoute{}, builder.WithPredicates(
			predicate.Funcs{
				CreateFunc: func(ce event.CreateEvent) bool {
					// we are only interested in GKEIPRoutes that are updated with
					// Accepted conditions by the main GKEIPRoute controller.
					// Hence we will not reconcile on Create event.
					return false
				},
			},
		)).
		Complete(r)
}

// LookupEndpointByPodNameAndNetwork looks up endpoint in a pod by namespace + pod name and a network id.
func (r *GKEIPRouteReconciler) LookupEndpointByPodNameAndNetwork(name string, networkID uint32) *endpoint.Endpoint {
	// don't support queuries when multinic is disabled and networkID is non-zero
	if !option.Config.EnableGoogleMultiNIC && networkID != 0 {
		return nil
	}
	// endpoints belonging to default network have a networkID value 0.
	if !option.Config.EnableGoogleMultiNIC || networkID == 0 {
		return r.LookupPodName(name)
	}
	eps := r.LookupEndpointsByPodName(name)
	for _, ep := range eps {
		if ep.DatapathConfiguration.NetworkID == networkID {
			return ep
		}
	}
	return nil
}

func (r *GKEIPRouteReconciler) networkID(ctx context.Context, networkName string) (uint32, error) {
	if networkv1.IsDefaultNetwork(networkName) {
		return 0, nil
	}
	var network networkv1.Network
	if err := r.Get(ctx, types.NamespacedName{Name: networkName}, &network); err != nil {
		return 0, err
	}
	return connector.GenerateNetworkID(&network), nil
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
