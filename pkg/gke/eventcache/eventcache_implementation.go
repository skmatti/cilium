// The file eventcache_implementation.go contains mostly unexported (hence the word
// "implementation") methods of the type HybridCache.
package eventcache

import (
	"math"

	eventcachetypes "github.com/cilium/cilium/pkg/gke/eventcache/types"
	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/time"
)

type kubeAPITimes struct {
	add    time.Time
	update time.Time
	del    time.Time
}

type metaEntry struct {
	kubeAPITimes
	lastObserved time.Time
}

type serviceEntry k8s.Service
type portEntry port
type endpointEntry struct {
	endpoint
	slices map[k8s.EndpointSliceID]struct{} // Only used with data from KubeAPI.
}

type port struct{}

type endpoint struct {
	terminating bool
}

type hybridCacheEvent struct {
	resourcedEvent resourcedEvent
	serviceID      eventcachetypes.ServiceID
	service        *k8s.Service
	ipPort         *loadbalancer.L3n4Addr
	endpoint       *endpoint
	endpointSet    *k8s.Endpoints
	sotw           map[eventcachetypes.ServiceID]ServiceWithPortsAndEndpoints
	source         eventcachetypes.Source
	time           time.Time
	swg            *lock.StoppableWaitGroup
}

type resource int

const (
	resourceUndefined resource = iota
	resourceService
	resourcePort
	resourceEndpoint
)

type apiEvent int

const (
	eventUpdate apiEvent = iota
	eventDelete
	eventUpdateMany
)

type resourcedEvent struct {
	sotw     bool
	resource resource
	event    apiEvent
}

var (
	updateService = resourcedEvent{resource: resourceService, event: eventUpdate}
	deleteService = resourcedEvent{resource: resourceService, event: eventDelete}

	updateEndpoint = resourcedEvent{resource: resourceEndpoint, event: eventUpdate}
	deleteEndpoint = resourcedEvent{resource: resourceEndpoint, event: eventDelete}

	updateManyEndpoints = resourcedEvent{resource: resourceEndpoint, event: eventUpdateMany}

	reportSotW = resourcedEvent{sotw: true}
)

type action int // Received update event may be an addition, a relevant modification, or an irrelevant modification (to be ignored by cilium). This is reflected by the type `action`.

const (
	actionNoOp action = iota
	actionAdd
	actionModify
	actionDelete
	actionDeleteFromSlice // Before endpoint is deleted from all slices, we treat this as actionNoOp apart from updating timestamps.
)

// ----- Actual processing happens below -----

func (h *HybridCache) processEvent(e *hybridCacheEvent) {
	defer e.swg.Done()
	switch e.resourcedEvent {
	case updateService:
		h.upsertService(e.serviceID, e.service, e.source, e.time)
	case updateEndpoint:
		h.upsertEndpointIntoSlice(e.serviceID, *e.ipPort, e.endpoint, nil, e.source, e.time)
	case updateManyEndpoints:
		h.updateManyEndpoints(e.serviceID, e.endpointSet, e.source, e.time)
	case deleteService:
		h.deleteService(e.serviceID, e.source, e.time)
	case deleteEndpoint:
		h.deleteEndpoint(e.serviceID, *e.ipPort, e.source, e.time)
	case reportSotW:
		h.updateStateOfTheWorld(e.sotw, e.time)
	}
}

// --- HybridCache private methods for upserts and deletions ---

func (h *HybridCache) upsertService(id eventcachetypes.ServiceID, n *k8s.Service, src eventcachetypes.Source, now time.Time) {
	h.touchServiceMetadata(id, now)
	act := h.cacheFrom[src].upsertService(id, n)
	if act == actionNoOp {
		return
	}
	h.reconcilePortEntries(id, src, now)
	h.reportServiceAndCleanup(id, act, src, now)
}

func (h *HybridCache) deleteService(id eventcachetypes.ServiceID, src eventcachetypes.Source, now time.Time) {
	act := h.cacheFrom[src].deleteService(id)
	if act == actionNoOp {
		return
	}
	h.touchServiceMetadata(id, now)
	h.deleteAllPorts(id, src, now)
	h.deleteAllEndpoints(id, src, now)
	h.reportServiceAndCleanup(id, act, src, now)
}

func (h *HybridCache) reconcilePortEntries(id eventcachetypes.ServiceID, src eventcachetypes.Source, now time.Time) {
	newPortSet := portMapToSet(h.cacheFrom[src].currentPorts(id))
	for p := range newPortSet {
		h.addPort(id, p, src, now)
	}
	for p := range h.cacheFrom[src].ports[id] {
		if _, ok := newPortSet[p]; !ok {
			h.deletePort(id, p, src, now)
		}
	}
}

func (h *HybridCache) addPort(id eventcachetypes.ServiceID, p loadbalancer.L4Addr, src eventcachetypes.Source, now time.Time) (act action) {
	h.touchPortMetadata(id, p, now)
	act = h.cacheFrom[src].addPort(id, p)
	if act == actionNoOp {
		return
	}
	h.reportPortAndCleanup(id, p, act, src, now)
	return
}

func (h *HybridCache) deletePort(id eventcachetypes.ServiceID, p loadbalancer.L4Addr, src eventcachetypes.Source, now time.Time) {
	act := h.cacheFrom[src].deletePort(id, p)
	if act == actionNoOp {
		return
	}
	h.touchPortMetadata(id, p, now)
	h.reportPortAndCleanup(id, p, act, src, now)
}

func (h *HybridCache) upsertEndpointIntoSlice(id eventcachetypes.ServiceID, e loadbalancer.L3n4Addr, n *endpoint, slice *k8s.EndpointSliceID, src eventcachetypes.Source, now time.Time) {
	h.touchEndpointMetadata(id, e, now)
	act := h.cacheFrom[src].upsertEndpointIntoSlice(id, e, n, slice)
	if act == actionNoOp {
		return
	}
	h.reportEndpointAndCleanup(id, e, act, src, now)
}

func (h *HybridCache) deleteEndpointFromSlice(id eventcachetypes.ServiceID, e loadbalancer.L3n4Addr, slice *k8s.EndpointSliceID, src eventcachetypes.Source, now time.Time) {
	act := h.cacheFrom[src].deleteEndpointFromSlice(id, e, slice)
	if act == actionNoOp {
		return
	}
	h.touchEndpointMetadata(id, e, now)
	if act == actionDeleteFromSlice {
		return
	}
	h.reportEndpointAndCleanup(id, e, act, src, now)
}

func (h *HybridCache) deleteEndpoint(id eventcachetypes.ServiceID, e loadbalancer.L3n4Addr, src eventcachetypes.Source, now time.Time) {
	h.deleteEndpointFromSlice(id, e, nil, src, now)
}

func (h *HybridCache) updateManyEndpoints(id eventcachetypes.ServiceID, endpoints *k8s.Endpoints, src eventcachetypes.Source, now time.Time) {
	current := make(map[loadbalancer.L3n4Addr]struct{})
	for addrCluster, b := range endpoints.Backends {
		for _, p := range b.Ports {
			ipPort := loadbalancer.NewL3n4Addr(p.Protocol, addrCluster, p.Port, loadbalancer.ScopeExternal)
			current[*ipPort] = struct{}{}
			h.upsertEndpointIntoSlice(id, *ipPort, &endpoint{terminating: b.Terminating}, &endpoints.EndpointSliceID, src, now)
		}
	}
	for ipPort, epEntry := range h.cacheFrom[src].endpoints[id] {
		if len(epEntry.slices) == 0 {
			log.Warningf("Endpoint %v of service %v belongs to zero EndpointSlices, deleting", ipPort, id)
			h.deleteEndpoint(id, ipPort, src, now)
			continue
		}
		_, existed := epEntry.slices[endpoints.EndpointSliceID]
		_, shouldExist := current[ipPort]
		if existed && !shouldExist {
			h.deleteEndpointFromSlice(id, ipPort, &endpoints.EndpointSliceID, src, now)
		}
	}
}

func (h *HybridCache) updateStateOfTheWorld(sotw map[eventcachetypes.ServiceID]ServiceWithPortsAndEndpoints, now time.Time) {
	// Create or update resources.
	for id, spe := range sotw {
		h.upsertService(id, spe.Service, eventcachetypes.TDxDS, now)
		for e, t := range spe.Endpoints {
			h.upsertEndpointIntoSlice(id, e, &endpoint{terminating: t}, nil, eventcachetypes.TDxDS, now)
		}
	}

	// Delete resources that are not present in sotw.
	for id := range h.cacheFrom[eventcachetypes.TDxDS].services {
		spe, svcPresent := sotw[id]
		for e := range h.cacheFrom[eventcachetypes.TDxDS].endpoints[id] {
			if _, endpointPresent := spe.Endpoints[e]; !endpointPresent {
				h.deleteEndpoint(id, e, eventcachetypes.TDxDS, now)
			}
		}
		if !svcPresent {
			h.deleteService(id, eventcachetypes.TDxDS, now)
		}
	}
}

/// --- cache methods for upserts and deletions ---

func (c *cache) upsertService(id eventcachetypes.ServiceID, n *k8s.Service) (act action) {
	c.ensurePortsEndpoints(id)
	old := (*k8s.Service)(c.services[id])
	act = actionModify
	switch {
	case old == nil:
		act = actionAdd
	case areServicesEqual(old, n):
		return actionNoOp
	}
	c.services[id] = (*serviceEntry)(n)
	return
}

func (c *cache) deleteService(id eventcachetypes.ServiceID) action {
	_, ok := c.services[id]
	if !ok { // already deleted
		return actionNoOp
	}
	delete(c.services, id)
	return actionDelete
}

func (c *cache) addPort(id eventcachetypes.ServiceID, p loadbalancer.L4Addr) action {
	old := c.ports[id][p]
	act := actionNoOp // Ports are empty structs, so there is nothing to modify.
	if old == nil {
		act = actionAdd
	}
	c.ports[id][p] = &portEntry{}
	return act
}

func (c *cache) deletePort(id eventcachetypes.ServiceID, p loadbalancer.L4Addr) action {
	_, ok := c.ports[id][p]
	if !ok { // Already deleted.
		return actionNoOp
	}
	delete(c.ports[id], p)
	return actionDelete
}

func (c *cache) upsertEndpointIntoSlice(id eventcachetypes.ServiceID, e loadbalancer.L3n4Addr, n *endpoint, sliceID *k8s.EndpointSliceID) action {
	c.ensurePortsEndpoints(id)
	act := actionModify
	if c.endpoints[id][e] == nil {
		act = actionAdd
		c.endpoints[id][e] = &endpointEntry{}
	} else if c.endpoints[id][e].endpoint == *n {
		act = actionNoOp
	}
	c.endpoints[id][e].endpoint = *n
	c.endpoints[id][e].addSlice(sliceID)
	return act
}

func (ee *endpointEntry) addSlice(s *k8s.EndpointSliceID) {
	if s == nil {
		return
	}
	if ee.slices == nil {
		ee.slices = make(map[k8s.EndpointSliceID]struct{})
	}
	ee.slices[*s] = struct{}{}
}

func (c *cache) deleteEndpointFromSlice(id eventcachetypes.ServiceID, e loadbalancer.L3n4Addr, slice *k8s.EndpointSliceID) action {
	endpoints, ok := c.endpoints[id]
	if !ok { // Whole service does not exist, nothing to delete.
		return actionNoOp
	}
	entry, ok := endpoints[e]
	if !ok { // Already deleted
		return actionNoOp
	}
	if slice == nil {
		delete(endpoints, e)
		return actionDelete
	}
	if _, ok := entry.slices[*slice]; !ok { // Already deleted
		return actionNoOp
	}
	delete(entry.slices, *slice)
	if len(entry.slices) == 0 {
		delete(endpoints, e)
		return actionDelete
	}
	return actionDeleteFromSlice
}

// --- metadata and metrics ---

func (h *HybridCache) touchServiceMetadata(id eventcachetypes.ServiceID, now time.Time) {
	if _, ok := h.meta.service[id]; !ok {
		h.meta.service[id] = &metaEntry{}
		h.meta.port[id] = make(map[loadbalancer.L4Addr]*metaEntry)
		h.meta.endpoint[id] = make(map[loadbalancer.L3n4Addr]*metaEntry)
	}
	h.meta.service[id].lastObserved = now
}

func (h *HybridCache) touchPortMetadata(id eventcachetypes.ServiceID, p loadbalancer.L4Addr, now time.Time) {
	// We only allow port manipulations via service manipulations in the API, so h.meta.port[id] should always be non-nil here.
	if _, ok := h.meta.port[id][p]; !ok {
		h.meta.port[id][p] = &metaEntry{}
	}
	h.meta.port[id][p].lastObserved = now
}

func (h *HybridCache) touchEndpointMetadata(id eventcachetypes.ServiceID, e loadbalancer.L3n4Addr, now time.Time) {
	h.touchServiceMetadata(id, now)
	// After calling touchServiceMetadata above, endpoints below should be guaranteed to be non-nil.
	endpoints := h.meta.endpoint[id]
	endpoint, ok := endpoints[e]
	if !ok {
		endpoints[e] = &metaEntry{}
		endpoint = endpoints[e]
	}
	endpoint.lastObserved = now
}

func (h *HybridCache) deleteServiceMetaAndData(id eventcachetypes.ServiceID) {
	delete(h.meta.service, id)
	delete(h.meta.port, id)
	delete(h.meta.endpoint, id)
	delete(h.cacheFrom[eventcachetypes.KubeAPI].services, id)
	delete(h.cacheFrom[eventcachetypes.TDxDS].services, id)
	delete(h.cacheFrom[eventcachetypes.KubeAPI].ports, id)
	delete(h.cacheFrom[eventcachetypes.TDxDS].ports, id)
	delete(h.cacheFrom[eventcachetypes.KubeAPI].endpoints, id)
	delete(h.cacheFrom[eventcachetypes.TDxDS].endpoints, id)
}

func (h *HybridCache) deleteAllPorts(id eventcachetypes.ServiceID, src eventcachetypes.Source, now time.Time) {
	h.reconcilePortEntries(id, src, now)
	delete(h.cacheFrom[src].ports, id)
}

func (h *HybridCache) deleteAllEndpoints(id eventcachetypes.ServiceID, src eventcachetypes.Source, now time.Time) {
	for e := range h.cacheFrom[src].endpoints[id] {
		h.deleteEndpoint(id, e, src, now)
	}
	delete(h.cacheFrom[src].endpoints, id)
}

func (h *HybridCache) deletePortMetaAndData(id eventcachetypes.ServiceID, p loadbalancer.L4Addr) {
	delete(h.meta.port[id], p)
	delete(h.cacheFrom[eventcachetypes.KubeAPI].ports[id], p)
	delete(h.cacheFrom[eventcachetypes.TDxDS].ports[id], p)
}

func (h *HybridCache) deleteEndpointMetaAndData(id eventcachetypes.ServiceID, e loadbalancer.L3n4Addr) {
	delete(h.meta.endpoint[id], e)
	delete(h.cacheFrom[eventcachetypes.KubeAPI].endpoints[id], e)
	delete(h.cacheFrom[eventcachetypes.TDxDS].endpoints[id], e)
}

func (h *HybridCache) reportServiceAndCleanup(id eventcachetypes.ServiceID, act action, src eventcachetypes.Source, now time.Time) {
	equal := h.areServicesFromBothSourcesEqual(id)
	data := calculateMetricData(act, &h.meta.service[id].kubeAPITimes, src, equal, now)
	data.resource = resourceService
	exportMetricsAndLog(data, combinedResourceKey{id, nil, nil})
	if act == actionDelete && equal && noPendingEvents(&h.meta.service[id].kubeAPITimes) {
		h.deleteServiceMetaAndData(id)
	}
}

func (h *HybridCache) reportPortAndCleanup(id eventcachetypes.ServiceID, p loadbalancer.L4Addr, act action, src eventcachetypes.Source, now time.Time) {
	equal := h.arePortsFromBothSourcesEqual(id, p)
	data := calculateMetricData(act, &h.meta.port[id][p].kubeAPITimes, src, equal, now)
	data.resource = resourcePort
	exportMetricsAndLog(data, combinedResourceKey{id, &p, nil})
	if act == actionDelete && equal && noPendingEvents(&h.meta.port[id][p].kubeAPITimes) {
		h.deletePortMetaAndData(id, p)
	}
}

func (h *HybridCache) reportEndpointAndCleanup(id eventcachetypes.ServiceID, e loadbalancer.L3n4Addr, act action, src eventcachetypes.Source, now time.Time) {
	equal := h.areEndpointsFromBothSourcesEqual(id, e)
	data := calculateMetricData(act, &h.meta.endpoint[id][e].kubeAPITimes, src, equal, now)
	data.resource = resourceEndpoint
	exportMetricsAndLog(data, combinedResourceKey{id, nil, &e})
	if act == actionDelete && equal && noPendingEvents(&h.meta.endpoint[id][e].kubeAPITimes) {
		h.deleteEndpointMetaAndData(id, e)
	}
}

type combinedResourceKey struct {
	eventcachetypes.ServiceID
	port     *loadbalancer.L4Addr
	endpoint *loadbalancer.L3n4Addr
}

func exportMetricsAndLog(metricData metricData, resourceKey combinedResourceKey) {
	if metricData.metricType == noMetric {
		return
	}

	switch metricData.resource {
	case resourceService:
		log.Debugf("Reported %s for event %v for resource %s %s from %v", metricData.metricType, metricData.action, metricData.resource, resourceKey.ServiceID, metricData.source)
	case resourcePort:
		log.Debugf("Reported %s for event %v for resource %s %s:%d(%s) from %v", metricData.metricType, metricData.action, metricData.resource, resourceKey.ServiceID, resourceKey.port.Port, resourceKey.port.Protocol, metricData.source)
	case resourceEndpoint:
		log.Debugf("Reported %s for event %v for resource %s %v/%d(%s) behind %s %s from %v", metricData.metricType, metricData.action, metricData.resource, resourceKey.endpoint.AddrCluster, resourceKey.endpoint.L4Addr.Port, resourceKey.endpoint.L4Addr.Protocol, resourceService, resourceKey.ServiceID, metricData.source)
	}

	switch metricData.metricType {
	case delay:
		log.Debugf("%s %s latency: %v", metricData.resource, metricData.action, metricData.duration.Seconds())
		exportLatencyMetric(metricData.duration, metricData.resource, metricData.action)
	case skipped:
		exportSkippedMetric(metricData.source, metricData.resource, metricData.action)
	case lost:
		exportUnmatchedMetric(metricData.source, metricData.resource, metricData.action)
	}
}

// --- checking for missed events or stale cache entries ---

func (h *HybridCache) periodicReview() {
	now := time.Now()

	// Check for missed events.
	h.checkMissing(now)

	// Delete stale cache entries.
	h.collectGarbage(now)
}

func (h *HybridCache) collectGarbage(now time.Time) {
	for svcKey, svcMeta := range h.meta.service {
		if svcMeta.lastObserved.Add(h.config.cacheEntryTTL).Before(now) {
			log.Infof("Deleting cache entries for service %v last seen at %v.", svcKey, svcMeta.lastObserved)
			h.deleteServiceMetaAndData(svcKey)
			continue
		}

		for portKey, portMeta := range h.meta.port[svcKey] {
			if portMeta.lastObserved.Add(h.config.cacheEntryTTL).Before(now) {
				log.Infof("Deleting cache entries for port %v last seen at %v.", portKey, portMeta.lastObserved)
				h.deletePortMetaAndData(svcKey, portKey)
			}
		}

		for endpointKey, endpointMeta := range h.meta.endpoint[svcKey] {
			if endpointMeta.lastObserved.Add(h.config.cacheEntryTTL).Before(now) {
				log.Infof("Deleting cache entries for endpoint %v last seen at %v.", endpointKey, endpointMeta.lastObserved)
				h.deleteEndpointMetaAndData(svcKey, endpointKey)
			}
		}
	}
}

func (h *HybridCache) checkMissing(now time.Time) {
	for svcKey, svcMeta := range h.meta.service {
		missing := checkForMissingEvents(&svcMeta.kubeAPITimes, now, h.config.matchingPeriod)
		for _, metricData := range missing {
			metricData.resource = resourceService
			exportMetricsAndLog(metricData, combinedResourceKey{svcKey, nil, nil})
		}

		for p, portMeta := range h.meta.port[svcKey] {
			missing := checkForMissingEvents(&portMeta.kubeAPITimes, now, h.config.matchingPeriod)
			for _, metricData := range missing {
				metricData.resource = resourcePort
				exportMetricsAndLog(metricData, combinedResourceKey{svcKey, &p, nil})
			}
		}

		for e, endpointMeta := range h.meta.endpoint[svcKey] {
			missing := checkForMissingEvents(&endpointMeta.kubeAPITimes, now, h.config.matchingPeriod)
			for _, metricData := range missing {
				metricData.resource = resourceEndpoint
				exportMetricsAndLog(metricData, combinedResourceKey{svcKey, nil, &e})
			}
		}
	}
}

func checkForMissingEvents(kubeAPITimes *kubeAPITimes, now time.Time, deadline time.Duration) (missing []metricData) {
	if metricData := checkForMissingEvent(&kubeAPITimes.add, now, actionAdd, deadline); metricData.metricType != noMetric {
		metricData.action = actionAdd
		missing = append(missing, metricData)
	}
	if metricData := checkForMissingEvent(&kubeAPITimes.update, now, actionModify, deadline); metricData.metricType != noMetric {
		metricData.action = actionModify
		missing = append(missing, metricData)
	}
	if metricData := checkForMissingEvent(&kubeAPITimes.del, now, actionDelete, deadline); metricData.metricType != noMetric {
		metricData.action = actionDelete
		missing = append(missing, metricData)
	}
	return
}

func checkForMissingEvent(kubeAPITime *time.Time, now time.Time, action action, deadline time.Duration) (toBeReported metricData) {
	if !kubeAPITime.IsZero() && kubeAPITime.Add(deadline).Before(now) {
		toBeReported.metricType = lost
		toBeReported.source = eventcachetypes.KubeAPI
		toBeReported.action = action
		*kubeAPITime = time.Time{}
	}
	return
}

// --- reporting metrics ---

type hybridCacheMetricType int

const (
	noMetric hybridCacheMetricType = iota
	skipped
	lost
	delay
)

type metricData struct {
	source     eventcachetypes.Source
	metricType hybridCacheMetricType
	resource   resource
	action     action
	duration   time.Duration
}

func calculateMetricData(act action, times *kubeAPITimes, src eventcachetypes.Source, equal bool, now time.Time) (toBeReported metricData) {
	if src == eventcachetypes.KubeAPI {
		return calculateMetricDataOnKubeAPIEvent(times, act, now)
	}
	return calculateMetricDataOnTDEvent(times, act, equal, now)
}

func calculateMetricDataOnKubeAPIEvent(times *kubeAPITimes, act action, now time.Time) (toBeReported metricData) {
	toBeReported.source = eventcachetypes.KubeAPI
	toBeReported.action = act

	var timeToSet *time.Time
	switch act {
	case actionAdd:
		timeToSet = &times.add
	case actionModify:
		timeToSet = &times.update
	case actionDelete:
		timeToSet = &times.del
	default:
		log.Error("Action should not be NoOp here.")
		return
	}
	if !timeToSet.IsZero() {
		toBeReported.metricType = skipped
	}
	*timeToSet = now
	return
}

func calculateMetricDataOnTDEvent(times *kubeAPITimes, act action, equal bool, now time.Time) (toBeReported metricData) {
	toBeReported.source = eventcachetypes.TDxDS
	toBeReported.action = act

	eligibleForMatch := equal

	var timeToCompare *time.Time

	switch act {
	case actionAdd:
		timeToCompare = &times.add
		// If the resource has been updated since creation in KubeAPI Server, it's creation status has been overridden, so we validate positively.
		eligibleForMatch = !times.update.IsZero() || eligibleForMatch
	case actionModify:
		timeToCompare = &times.update
	case actionDelete:
		timeToCompare = &times.del
	default:
		log.Error("Action should not be NoOp here.")
		return
	}

	if timeToCompare.IsZero() {
		toBeReported.metricType = lost
	} else {
		if !eligibleForMatch {
			toBeReported.metricType = skipped
		} else {
			toBeReported.metricType = delay
			toBeReported.duration = now.Sub(*timeToCompare)
			*timeToCompare = time.Time{}
		}
	}
	return
}

func exportLatencyMetric(d time.Duration, resource resource, action action) {
	seconds := math.Round(d.Seconds()*10) / 10 // Limit accuracy to tenths of a second to facilitate testing.
	resourceEventDelay.WithLabelValues(resource.String(), action.String()).Observe(seconds)
}

func exportSkippedMetric(src eventcachetypes.Source, resource resource, action action) {
	resourceEventSkipped.WithLabelValues(src.String(), resource.String(), action.String()).Add(1)
}

func exportUnmatchedMetric(src eventcachetypes.Source, resource resource, action action) {
	resourceEventLost.WithLabelValues(src.String(), resource.String(), action.String()).Add(1)
}
