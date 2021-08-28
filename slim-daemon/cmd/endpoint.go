package cmd

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"time"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/addressing"
	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/endpointmanager/idallocator"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/identity/cache"
	"github.com/cilium/cilium/pkg/identity/identitymanager"
	identitymodel "github.com/cilium/cilium/pkg/identity/model"
	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/labelsfilter"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/slim-daemon/k8s"
	"github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/types"
)

type EndpointManager struct {
	// mutex protects endpoints and endpointsAux
	mutex lock.RWMutex

	// endpoints is the global list of endpoints indexed by ID. mutex must
	// be held to read and write.
	endpoints map[types.NamespacedName]*Endpoint

	EndpointResourceSynchronizer
}

type IdentityAllocator interface {
	// AllocateIdentity allocates an identity described by the specified labels.
	AllocateIdentity(context.Context, labels.Labels, bool, identity.NumericIdentity) (*identity.Identity, bool, error)

	// Release is the reverse operation of AllocateIdentity() and releases the
	// specified identity.
	Release(context.Context, *identity.Identity, bool) (released bool, err error)
}

type Endpoint struct {
	// ID of the endpoint, unique in the scope of the node
	ID uint16

	// SecurityIdentity is the security identity of this endpoint. This is computed from
	// the endpoint's labels.
	SecurityIdentity *identity.Identity `json:"SecLabel"`

	// K8sPodName is the Kubernetes pod name of the endpoint
	K8sPodName string

	// K8sNamespace is the Kubernetes namespace of the endpoint
	K8sNamespace string

	// IPv6 is the IPv6 address of the endpoint
	IPv6 addressing.CiliumIPv6

	// IPv4 is the IPv4 address of the endpoint
	IPv4 addressing.CiliumIPv4

	// identityRevision is incremented each time the identity label
	// information of the endpoint has changed
	identityRevision int

	// OpLabels is the endpoint's label configuration
	OpLabels labels.OpLabels

	logger *logrus.Entry

	allocator IdentityAllocator

	// controllers is the list of async controllers syncing the endpoint to
	// other resources
	controllers *controller.Manager

	pod *slim_corev1.Pod

	// mutex protects write operations to this endpoint structure
	mutex lock.RWMutex

	aliveCtx    context.Context
	aliveCancel context.CancelFunc
}

func NewEndpointManager() *EndpointManager {
	return &EndpointManager{
		endpoints: map[types.NamespacedName]*Endpoint{},
	}
}

func NewEndpoint(pod *slim_corev1.Pod, allocator IdentityAllocator) (*Endpoint, error) {
	ep := &Endpoint{
		K8sNamespace: pod.Namespace,
		K8sPodName:   pod.Name,
		OpLabels:     labels.NewOpLabels(),
		controllers:  controller.NewManager(),
		pod:          pod,
		allocator:    allocator,
	}

	if len(pod.Status.PodIPs) == 0 {
		return ep, errors.New("pod doesn't have PodIPs")
	}

	ep.logger = log.WithField("pod", pod.Namespace+"/"+pod.Name)

	_, lbls, _, err := k8s.GetPodMetadata(pod)
	if err != nil {
		return ep, err
	}

	log.Debugf("lables: %v", lbls)

	k8sLbls := labels.Map2Labels(lbls, labels.LabelSourceK8s)
	identityLabels, infoLabels := labelsfilter.Filter(k8sLbls)

	log.Debugf("identity lables: %v", identityLabels)

	ep.UpdateLabels(context.Background(), identityLabels, infoLabels, true)

	if ep.SecurityIdentity == nil {
		ep.SecurityIdentity = identity.LookupReservedIdentity(identity.ReservedIdentityInit)
	}
	ep.SecurityIdentity.Sanitize()

	for _, ip := range pod.Status.PodIPs {
		if net.ParseIP(ip.IP).To4() != nil {
			ipv4, err := addressing.NewCiliumIPv4(ip.IP)
			if err != nil {
				return ep, err
			}
			ep.IPv4 = ipv4
		} else {
			ipv6, err := addressing.NewCiliumIPv6(ip.IP)
			if err != nil {
				return ep, err
			}
			ep.IPv6 = ipv6
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	ep.aliveCancel = cancel
	ep.aliveCtx = ctx

	return ep, nil
}

// lockAlive returns error if endpoint was removed, locks underlying mutex otherwise
func (e *Endpoint) lockAlive() error {
	e.mutex.Lock()
	return nil
}

// rlockAlive returns error if endpoint was removed, read locks underlying mutex otherwise
func (e *Endpoint) rlockAlive() error {
	e.mutex.RLock()
	return nil
}

// Unlock unlocks endpoint mutex
func (e *Endpoint) unlock() {
	e.mutex.Unlock()
}

// runlock read unlocks endpoint mutex
func (e *Endpoint) runlock() {
	e.mutex.RUnlock()
}

// unconditionalRLock should be used only for reporting endpoint state
func (e *Endpoint) unconditionalRLock() {
	e.mutex.RLock()
}

// unconditionalLock should be used only for locking endpoint for
// - setting its state to StateDisconnected
// - handling regular Lock errors
// - reporting endpoint status (like in LogStatus method)
// Use Lock in all other cases
func (e *Endpoint) unconditionalLock() {
	e.mutex.Lock()
}

func (e *Endpoint) UpdateLabels(ctx context.Context, identityLabels, infoLabels labels.Labels, blocking bool) (regenTriggered bool) {
	log.WithFields(logrus.Fields{
		logfields.IdentityLabels: identityLabels.String(),
		logfields.InfoLabels:     infoLabels.String(),
	}).Debug("Refreshing labels of endpoint")

	e.mutex.Lock()

	// e.replaceInformationLabels(infoLabels)
	// replace identity labels and update the identity if labels have changed
	rev := e.replaceIdentityLabels(identityLabels)
	e.mutex.Unlock()
	if rev != 0 {
		return e.runIdentityResolver(ctx, rev, blocking)
	}

	return false
}

// GetID returns the endpoint's ID as a 64-bit unsigned integer.
func (e *Endpoint) GetID() uint64 {
	return uint64(e.ID)
}

// GetK8sPodName returns the name of the pod if the endpoint represents a
// Kubernetes pod
func (e *Endpoint) GetK8sPodName() string {
	e.unconditionalRLock()
	k8sPodName := e.K8sPodName
	e.runlock()

	return k8sPodName
}

// GetK8sNamespace returns the name of the pod if the endpoint represents a
// Kubernetes pod
func (e *Endpoint) GetK8sNamespace() string {
	e.unconditionalRLock()
	ns := e.K8sNamespace
	e.runlock()
	return ns
}

// GetK8sNamespaceAndPodName returns the corresponding namespace and pod
// name for this endpoint.
func (e *Endpoint) GetK8sNamespaceAndPodName() string {
	e.unconditionalRLock()
	defer e.runlock()

	return e.getK8sNamespaceAndPodName()
}

// GetSecurityIdentity returns the security identity of the endpoint. It assumes
// the endpoint's mutex is held.
func (e *Endpoint) GetSecurityIdentity() (*identity.Identity, error) {
	if err := e.rlockAlive(); err != nil {
		return nil, err
	}
	defer e.runlock()
	return e.SecurityIdentity, nil
}

// SetPod sets the pod related to this endpoint.
func (e *Endpoint) SetPod(pod *slim_corev1.Pod) {
	e.unconditionalLock()
	e.pod = pod
	e.unlock()
}

// GetPod retrieves the pod related to this endpoint
func (e *Endpoint) GetPod() *slim_corev1.Pod {
	e.unconditionalRLock()
	pod := e.pod
	e.runlock()
	return pod
}

func (e *Endpoint) getK8sNamespaceAndPodName() string {
	return e.K8sNamespace + "/" + e.K8sPodName
}

// ModifyIdentityLabels changes the custom and orchestration identity labels of an endpoint.
// Labels can be added or deleted. If a label change is performed, the
// endpoint will receive a new identity and will be regenerated. Both of these
// operations will happen in the background.
func (e *Endpoint) ModifyIdentityLabels(addLabels, delLabels labels.Labels) error {
	if err := e.lockAlive(); err != nil {
		return err
	}

	changed, err := e.OpLabels.ModifyIdentityLabels(addLabels, delLabels)
	if err != nil {
		e.unlock()
		return err
	}

	var rev int

	if changed {
		// Mark with StateWaitingForIdentity, it will be set to
		// StateWaitingToRegenerate after the identity resolution has been
		// completed
		// e.setState(StateWaitingForIdentity, "Triggering identity resolution due to updated identity labels")

		e.identityRevision++
		rev = e.identityRevision
	}
	e.unlock()

	if changed {
		e.runIdentityResolver(context.Background(), rev, false)
	}
	return nil
}

// getLogger returns a logrus object
func (e *Endpoint) getLogger() *logrus.Entry {
	return e.logger
}

// Logger returns a logrus object with EndpointID, containerID and the Endpoint
// revision fields. The caller must specify their subsystem.
func (e *Endpoint) Logger(subsystem string) *logrus.Entry {
	if e == nil {
		return log.WithField(logfields.LogSubsys, subsystem)
	}

	return e.getLogger().WithField(logfields.LogSubsys, subsystem)
}

// runIdentityResolver resolves the numeric identity for the set of labels that
// are currently configured on the endpoint.
//
// Must be called with e.mutex NOT held.
func (e *Endpoint) runIdentityResolver(ctx context.Context, myChangeRev int, blocking bool) (regenTriggered bool) {
	err := e.rlockAlive()
	if err != nil {
		// If a labels update and an endpoint delete API request arrive
		// in quick succession, this could occur; in that case, there's
		// no point updating the controller.
		e.getLogger().WithError(err).Info("Cannot run labels resolver")
		return false
	}
	newLabels := e.OpLabels.IdentityLabels()
	e.runlock()
	scopedLog := e.getLogger().WithField(logfields.IdentityLabels, newLabels)

	scopedLog.Info("Resolving identity labels (blocking)")
	_, err = e.identityLabelsChanged(ctx, myChangeRev)
	switch err {
	case ErrNotAlive:
		scopedLog.Debug("not changing endpoint identity because endpoint is in process of being removed")
		return false
	default:
		if err != nil {
			scopedLog.WithError(err).Warn("Error changing endpoint identity")
		}
	}

	return false
}

func (e *Endpoint) replaceIdentityLabels(l labels.Labels) int {
	if l == nil {
		return e.identityRevision
	}

	changed := e.OpLabels.ReplaceIdentityLabels(l, log)
	rev := 0
	if changed {
		e.identityRevision++
		rev = e.identityRevision
	}

	return rev
}

func (e *Endpoint) identityLabelsChanged(ctx context.Context, myChangeRev int) (regenTriggered bool, err error) {
	// e.setState() called below, can't take a read lock.
	if err := e.lockAlive(); err != nil {
		return false, ErrNotAlive
	}

	newLabels := e.OpLabels.IdentityLabels()
	elog := log.WithFields(logrus.Fields{
		logfields.EndpointID:     e.ID,
		logfields.IdentityLabels: newLabels,
	})

	// Since we unlocked the endpoint and re-locked, the label update may already be obsolete
	if e.identityResolutionIsObsolete(myChangeRev) {
		e.unlock()
		elog.Debug("Endpoint identity has changed, aborting resolution routine in favour of new one")
		return false, nil
	}

	if e.SecurityIdentity != nil && e.SecurityIdentity.Labels.Equals(newLabels) {
		// Sets endpoint state to ready if was waiting for identity
		// if e.getState() == StateWaitingForIdentity {
		// 	e.setState(StateReady, "Set identity for this endpoint")
		// }
		e.unlock()
		elog.Debug("Endpoint labels unchanged, skipping resolution of identity")
		return false, nil
	}

	// Unlock the endpoint mutex for the possibly long lasting kvstore operation
	e.unlock()
	elog.Debug("Resolving identity for labels")

	allocateCtx, cancel := context.WithTimeout(ctx, 2*time.Minute) // KVstoreConnectivityTimeout
	defer cancel()

	allocatedIdentity, _, err := e.allocator.AllocateIdentity(allocateCtx, newLabels, true, identity.InvalidIdentity)
	if err != nil {
		err = fmt.Errorf("unable to resolve identity: %s", err)
		return false, err
	}

	// When releasing identities after allocation due to either failure of
	// allocation or due a no longer used identity we want to operation to
	// continue even if the parent has given up. Enforce a timeout of two
	// minutes to avoid blocking forever but give plenty of time to release
	// the identity.
	releaseCtx, cancel := context.WithTimeout(ctx, 2*time.Minute) // 2min timeout
	defer cancel()

	releaseNewlyAllocatedIdentity := func() {
		_, err := e.allocator.Release(releaseCtx, allocatedIdentity, false)
		if err != nil {
			// non fatal error as keys will expire after lease expires but log it
			elog.WithFields(logrus.Fields{logfields.Identity: allocatedIdentity.ID}).
				WithError(err).Warn("Unable to release newly allocated identity again")
		}
	}

	if err := e.lockAlive(); err != nil {
		releaseNewlyAllocatedIdentity()
		return false, err
	}

	// Since we unlocked the endpoint and re-locked, the label update may already be obsolete
	if e.identityResolutionIsObsolete(myChangeRev) {
		e.unlock()

		releaseNewlyAllocatedIdentity()

		return false, nil
	}

	// If endpoint has an old identity, defer release of it to the end of
	// the function after the endpoint structured has been unlocked again
	oldIdentity := e.SecurityIdentity
	if oldIdentity != nil {
		// The identity of the endpoint is changing, delay the use of
		// the identity by a grace period to give all other cluster
		// nodes a chance to adjust their policies first. This requires
		// to unlock the endpoit and then lock it again.
		//
		// If the identity change is from init -> *, don't delay the
		// use of the identity as we want the init duration to be as
		// short as possible.
		if allocatedIdentity.ID != oldIdentity.ID && oldIdentity.ID != identity.ReservedIdentityInit {
			e.unlock()

			elog.Debugf("Applying grace period before regeneration due to identity change")
			time.Sleep(option.Config.IdentityChangeGracePeriod)

			if err := e.lockAlive(); err != nil {
				releaseNewlyAllocatedIdentity()
				return false, err
			}

			// Since we unlocked the endpoint and re-locked, the label update may already be obsolete
			if e.identityResolutionIsObsolete(myChangeRev) {
				e.unlock()
				releaseNewlyAllocatedIdentity()
				return false, nil
			}
		}
	}

	elog.WithFields(logrus.Fields{logfields.Identity: allocatedIdentity.StringID()}).
		Debug("Assigned new identity to endpoint")

	e.SetIdentity(allocatedIdentity, false)

	if oldIdentity != nil {
		_, err := e.allocator.Release(releaseCtx, oldIdentity, false)
		if err != nil {
			elog.WithFields(logrus.Fields{logfields.Identity: oldIdentity.ID}).
				WithError(err).Warn("Unable to release old endpoint identity")
		}
	}

	// Trigger the sync-to-k8s-ciliumendpoint controller to sync the new
	// endpoint's identity.
	e.controllers.TriggerController(EndpointSyncControllerName(e.ID))

	e.mutex.Unlock()

	return regenTriggered, nil
}

// EndpointSyncControllerName returns the controller name to synchronize
// endpoint in to kubernetes.
func EndpointSyncControllerName(epID uint16) string {
	return fmt.Sprintf("sync-to-k8s-ciliumendpoint (%v)", epID)
}

// SetIdentity resets endpoint's policy identity to 'id'.
// Caller triggers policy regeneration if needed.
// Called with e.mutex Lock()ed
func (e *Endpoint) SetIdentity(identity *identity.Identity, newEndpoint bool) {
	oldIdentity := "no identity"
	if e.SecurityIdentity != nil {
		oldIdentity = e.SecurityIdentity.StringID()
	}

	// Current security identity for endpoint is its old identity - delete its
	// reference from global identity manager, add add a reference to the new
	// identity for the endpoint.
	if newEndpoint {
		// TODO - GH-9354.
		identitymanager.Add(identity)
	} else {
		identitymanager.RemoveOldAddNew(e.SecurityIdentity, identity)
	}
	e.SecurityIdentity = identity
	e.replaceIdentityLabels(identity.Labels)

	// Sets endpoint state to ready if was waiting for identity
	// if e.getState() == StateWaitingForIdentity {
	// 	e.setState(StateReady, "Set identity for this endpoint")
	// }

	// Whenever the identity is updated, propagate change to key-value store
	// of IP to identity mapping.
	// e.runIPIdentitySync(e.IPv4)
	// e.runIPIdentitySync(e.IPv6)

	if oldIdentity != identity.StringID() {
		e.getLogger().WithFields(logrus.Fields{
			logfields.Identity:       identity.StringID(),
			logfields.OldIdentity:    oldIdentity,
			logfields.IdentityLabels: identity.Labels.String(),
		}).Info("Identity of endpoint changed")
	}
}

func (mgr *EndpointManager) Expose(ep *Endpoint) error {
	var (
		err error
	)

	scopedLog := log.WithField("endpoint", ep.K8sNamespace+"/"+ep.K8sPodName)
	scopedLog.Info("expose endpoint")

	index := types.NamespacedName{
		Namespace: ep.K8sNamespace,
		Name:      ep.K8sPodName,
	}

	mgr.mutex.Lock()
	defer mgr.mutex.Unlock()

	mgr.endpoints[index] = ep

	ep.ID, err = mgr.AllocateID(ep.ID)
	if err != nil {
		return err
	}

	scopedLog.WithField("id", ep.ID).Info("id allocated")

	mgr.RunK8sCiliumEndpointSync(ep)

	return nil
}

func (mgr *EndpointManager) Unexpose(ep *Endpoint) error {
	scopedLog := log.WithField("endpoint", ep.K8sNamespace+"/"+ep.K8sPodName)
	scopedLog.Info("unexpose endpoint")

	index := types.NamespacedName{
		Namespace: ep.K8sNamespace,
		Name:      ep.K8sPodName,
	}

	mgr.mutex.Lock()
	defer mgr.mutex.Unlock()

	if err := mgr.ReleaseID(ep); err != nil {
		return err
	}

	scopedLog.WithField("id", ep.ID).Info("id released")

	delete(mgr.endpoints, index)

	ep.controllers.RemoveAll()

	return nil
}

func (e *Endpoint) identityResolutionIsObsolete(myChangeRev int) bool {
	// Check if the endpoint has since received a new identity revision, if
	// so, abort as a new resolution routine will have been started.
	if myChangeRev != e.identityRevision {
		return true
	}

	return false
}

// UpdateController updates the controller with the specified name with the
// provided list of parameters in endpoint's list of controllers.
func (e *Endpoint) UpdateController(name string, params controller.ControllerParams) {
	params.Context = e.aliveCtx
	e.controllers.UpdateController(name, params)
}

// For updating, something like this
func (mgr *EndpointManager) UpdateLabels(ep *Endpoint) {
}

func (mgr *EndpointManager) Lookup(namespace, name string) (*Endpoint, error) {
	index := types.NamespacedName{
		Namespace: namespace,
		Name:      name,
	}

	if ep, ok := mgr.endpoints[index]; ok {
		return ep, nil
	} else {
		return nil, errNotFound
	}
}

// AllocateID checks if the ID can be reused. If it cannot, returns an error.
// If an ID of 0 is provided, a new ID is allocated. If a new ID cannot be
// allocated, returns an error.
func (mgr *EndpointManager) AllocateID(currID uint16) (uint16, error) {
	var newID uint16
	if currID != 0 {
		if err := idallocator.Reuse(currID); err != nil {
			return 0, fmt.Errorf("unable to reuse endpoint ID: %s", err)
		}
		newID = currID
	} else {
		id := idallocator.Allocate()
		if id == uint16(0) {
			return 0, fmt.Errorf("no more endpoint IDs available")
		}
		newID = id
	}

	return newID, nil
}

// ReleaseID releases the ID of the specified endpoint from the EndpointManager.
// Returns an error if the ID cannot be released.
func (mgr *EndpointManager) ReleaseID(ep *Endpoint) error {
	return idallocator.Release(ep.ID)
}

func (mgr *EndpointManager) removeSecurityIdentity(e *Endpoint) error {
	if e.SecurityIdentity != nil {
		// Restored endpoint may be created with a reserved identity of 5
		// (init), which is not registered in the identity manager and
		// therefore doesn't need to be removed.
		if e.SecurityIdentity.ID != identity.ReservedIdentityInit {
			identitymanager.Remove(e.SecurityIdentity)
		}

		releaseCtx, cancel := context.WithTimeout(context.Background(), 2*time.Minute) // KVstoreConnectivityTimeout
		defer cancel()

		_, err := e.allocator.Release(releaseCtx, e.SecurityIdentity, false)
		if err != nil {
			return err
		}
		e.SecurityIdentity = nil
	}

	return nil
}

// GetCiliumEndpointStatus creates a cilium_v2.EndpointStatus of an endpoint.
// See cilium_v2.EndpointStatus for a detailed explanation of each field.
func (e *Endpoint) GetCiliumEndpointStatus() *cilium_v2.EndpointStatus {
	e.mutex.RLock()
	defer e.mutex.RUnlock()

	status := &cilium_v2.EndpointStatus{
		ID:         int64(e.ID),
		Identity:   getEndpointIdentity(identitymodel.CreateModel(e.SecurityIdentity)),
		Networking: getEndpointNetworking(e.getModelNetworkingRLocked()),
		// ExternalIdentifiers: e.getModelEndpointIdentitiersRLocked(),
		//State:               compressEndpointState(e.getModelCurrentStateRLocked()),
		//Encryption:          cilium_v2.EncryptionSpec{Key: int(node.GetIPsecKeyIdentity())},
		//NamedPorts:          e.getNamedPortsModel(),
	}

	return status
}

func (e *Endpoint) getModelNetworkingRLocked() *models.EndpointNetworking {
	return &models.EndpointNetworking{
		Addressing: []*models.AddressPair{{
			IPV4: e.IPv4.String(),
			IPV6: e.IPv6.String(),
		}},
		// InterfaceIndex: int64(e.ifIndex),
		// InterfaceName:  e.ifName,
		// Mac:            e.mac.String(),
		// HostMac:        e.nodeMAC.String(),
	}
}

func getEndpointNetworking(mdlNetworking *models.EndpointNetworking) (networking *cilium_v2.EndpointNetworking) {
	if mdlNetworking == nil {
		return nil
	}
	networking = &cilium_v2.EndpointNetworking{
		Addressing: make(cilium_v2.AddressPairList, len(mdlNetworking.Addressing)),
	}
	log.WithField("ip", node.GetIPv4().String()).Info("Set NodeIP")
	networking.NodeIP = node.GetIPv4().String()

	for i, pair := range mdlNetworking.Addressing {
		networking.Addressing[i] = &cilium_v2.AddressPair{
			IPV4: pair.IPV4,
			IPV6: pair.IPV6,
		}
	}

	networking.Addressing.Sort()
	return
}

func getEndpointIdentity(mdlIdentity *models.Identity) (identity *cilium_v2.EndpointIdentity) {
	if mdlIdentity == nil {
		return
	}
	identity = &cilium_v2.EndpointIdentity{
		ID: mdlIdentity.ID,
	}

	identity.Labels = make([]string, len(mdlIdentity.Labels))
	copy(identity.Labels, mdlIdentity.Labels)
	sort.Strings(identity.Labels)
	return
}

type dummyIdentityAllocatorOwner struct {
}

func (dummyIdentityAllocatorOwner) UpdateIdentities(added, deleted cache.IdentityCache) {}

func (dummyIdentityAllocatorOwner) GetNodeSuffix() string {
	return ""
}
