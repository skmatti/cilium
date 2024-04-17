// Package eventcache implements the Hybrid Cache. The Hybrid Cache receives
// the information on services (including their ports) and endpoints from two
// sources (hence the word "hybrid"): the Traffic Director and the eventcachetypes.KubeAPI
// Server. In its current form, the Hybrid Cache compares the information from
// these sources, calculates the latency etc.
//
// The file eventcache_interface.go contains exported functions, mostly methods
// of the type HybridCache.
package eventcache

import (
	"time"

	eventcachetypes "github.com/cilium/cilium/pkg/gke/eventcache/types"
	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

var log = logging.DefaultLogger.WithField(logfields.LogSubsys, "eventcache")

const (
	// reviewPeriod is the time between checks for missed events or stale cache entries.
	reviewPeriod  = time.Minute
	cacheEntryTTL = 10 * time.Minute // TODO(b/320922703) Review cacheEntryTTL before going live on prod.

	// When an event arrives from one source, but does not arrive from the other within the prescribed period,
	// we consider the latter event to be missed.
	matchingPeriod        = 6 * time.Minute
	channelBufferSize int = 1000
)

type hybridCacheConfig struct {
	reviewPeriod      time.Duration
	cacheEntryTTL     time.Duration
	matchingPeriod    time.Duration
	channelBufferSize int
}

type cache struct {
	services  map[eventcachetypes.ServiceID]*serviceEntry
	ports     map[eventcachetypes.ServiceID]map[loadbalancer.L4Addr]*portEntry
	endpoints map[eventcachetypes.ServiceID]map[loadbalancer.L3n4Addr]*endpointEntry
}

// metaCache stores metadata about cached resources, more specifically timestamps
// for addition, update, deletion and the last observation.
type metaCache struct {
	service  map[eventcachetypes.ServiceID]*metaEntry
	port     map[eventcachetypes.ServiceID]map[loadbalancer.L4Addr]*metaEntry
	endpoint map[eventcachetypes.ServiceID]map[loadbalancer.L3n4Addr]*metaEntry
}

type HybridCache struct {
	cacheFrom    [2]*cache
	meta         *metaCache
	events       chan *hybridCacheEvent
	reviewTicker *time.Ticker
	config       *hybridCacheConfig
}

func New() *HybridCache {
	config := hybridCacheConfig{
		reviewPeriod:      reviewPeriod,
		cacheEntryTTL:     cacheEntryTTL,
		matchingPeriod:    matchingPeriod,
		channelBufferSize: channelBufferSize,
	}
	return new(&config)
}

func new(config *hybridCacheConfig) *HybridCache {
	n := HybridCache{
		meta: &metaCache{
			service:  make(map[eventcachetypes.ServiceID]*metaEntry),
			port:     make(map[eventcachetypes.ServiceID]map[loadbalancer.L4Addr]*metaEntry),
			endpoint: make(map[eventcachetypes.ServiceID]map[loadbalancer.L3n4Addr]*metaEntry),
		},
		events:       make(chan *hybridCacheEvent, config.channelBufferSize),
		reviewTicker: time.NewTicker(config.reviewPeriod),
		config:       config,
	}
	n.cacheFrom[eventcachetypes.KubeAPI] = &cache{
		services:  make(map[eventcachetypes.ServiceID]*serviceEntry),
		ports:     make(map[eventcachetypes.ServiceID]map[loadbalancer.L4Addr]*portEntry),
		endpoints: make(map[eventcachetypes.ServiceID]map[loadbalancer.L3n4Addr]*endpointEntry),
	}
	n.cacheFrom[eventcachetypes.TDxDS] = &cache{
		services:  make(map[eventcachetypes.ServiceID]*serviceEntry),
		ports:     make(map[eventcachetypes.ServiceID]map[loadbalancer.L4Addr]*portEntry),
		endpoints: make(map[eventcachetypes.ServiceID]map[loadbalancer.L3n4Addr]*endpointEntry),
	}
	return &n
}

func (h *HybridCache) Start() {
	log.Info("Hybrid Cache is starting.")
	go h.processingLoop()
}

func (h *HybridCache) Stop() {
	close(h.events)
	h.reviewTicker.Stop()
}

func (h *HybridCache) processingLoop() {
	for {
		select {
		case e, ok := <-h.events:
			if !ok {
				log.Info("Hybrid Cache is stopping.")
				return
			}
			h.processEvent(e)
		case <-h.reviewTicker.C:
			h.periodicReview()
		}

	}
}

// ----- Addition methods -----

func (h *HybridCache) UpdateService(id eventcachetypes.ServiceID, service *k8s.Service, src eventcachetypes.Source, swg *lock.StoppableWaitGroup) {
	swg.Add()
	if service == nil {
		log.Errorf("UpdateService: service is nil for %v from %v", id, src)
		swg.Done()
		return
	}
	event := &hybridCacheEvent{
		resourcedEvent: updateService,
		serviceID:      id,
		service:        service,
		source:         src,
		time:           time.Now(),
		swg:            swg,
	}
	h.events <- event
}

// UpdateEndpoint is currently only used with Traffic Director xDS stream.
func (h *HybridCache) UpdateEndpoint(id eventcachetypes.ServiceID, ipPort loadbalancer.L3n4Addr, terminating bool, src eventcachetypes.Source, swg *lock.StoppableWaitGroup) {
	swg.Add()
	event := &hybridCacheEvent{
		resourcedEvent: updateEndpoint,
		serviceID:      id,
		ipPort:         &ipPort,
		endpoint:       &endpoint{terminating: terminating},
		source:         src,
		time:           time.Now(),
		swg:            swg,
	}
	h.events <- event
}

// UpdateManyEndpoints is currently only used with Kubernetes watchers.
func (h *HybridCache) UpdateManyEndpoints(id eventcachetypes.ServiceID, newEndpoints *k8s.Endpoints, src eventcachetypes.Source, swg *lock.StoppableWaitGroup) {
	swg.Add()
	event := &hybridCacheEvent{
		resourcedEvent: updateManyEndpoints,
		serviceID:      id,
		endpointSet:    newEndpoints,
		source:         src,
		time:           time.Now(),
		swg:            swg,
	}
	h.events <- event
}

// ----- Deletion methods -----

func (h *HybridCache) DeleteService(id eventcachetypes.ServiceID, src eventcachetypes.Source, swg *lock.StoppableWaitGroup) {
	swg.Add()
	event := &hybridCacheEvent{
		resourcedEvent: deleteService,
		serviceID:      id,
		source:         src,
		time:           time.Now(),
		swg:            swg,
	}
	h.events <- event
}

func (h *HybridCache) DeleteEndpoint(id eventcachetypes.ServiceID, ipPort loadbalancer.L3n4Addr, src eventcachetypes.Source, swg *lock.StoppableWaitGroup) {
	swg.Add()
	event := &hybridCacheEvent{
		resourcedEvent: deleteEndpoint,
		serviceID:      id,
		ipPort:         &ipPort,
		source:         src,
		time:           time.Now(),
		swg:            swg,
	}
	h.events <- event
}

// ----- Method for SotW xDS -----

// Type of entries for the map describing State of the World.
type ServiceWithPortsAndEndpoints struct {
	// Service constains information about Service and Ports.
	Service *k8s.Service
	// Endpoints is the set of endpoints for the service.
	Endpoints map[loadbalancer.L3n4Addr]bool
}

// UpdateStateOfTheWorld updates the HybridCache with SotW xDS feed from Traffic Director.
func (h *HybridCache) UpdateStateOfTheWorld(sotw map[eventcachetypes.ServiceID]ServiceWithPortsAndEndpoints, swg *lock.StoppableWaitGroup) {
	swg.Add()
	event := &hybridCacheEvent{
		resourcedEvent: reportSotW,
		sotw:           sotw,
		source:         eventcachetypes.TDxDS,
		time:           time.Now(),
		swg:            swg,
	}
	h.events <- event
}
