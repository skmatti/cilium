/*
Copyright 2022 Google LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

/*
This file contains the logic for ILB services running in GDC-H. It extends the
service cache logic which is used by both cilium-agent (anetd) and
clustermesh-apiserver.

*/

package k8s

import (
	"fmt"
	"net"
	"reflect"
	"strings"

	"github.com/cilium/cilium/pkg/annotation"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	slimv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
	serviceStore "github.com/cilium/cilium/pkg/service/store"
	"github.com/sirupsen/logrus"
)

const (
	serviceAnnotationKey         = "networking.gke.io/load-balancer-type"
	serviceAnnotationValue       = "internal"
	globalServiceAnnotationValue = "global-internal"
	serviceTypeKey               = "serviceType"
	globalServiceTrue            = "true"
)

// generateServiceName creates a unique service name by using the cluster name as a prefix.
// Using a different internal name for the service allows us to avoid conflicts with local services with the same namespace/name.
func generateClusterServiceName(service *serviceStore.ClusterService) string {
	return fmt.Sprintf("%s-%s", service.Cluster, service.Name)
}

// ilbExternalUpdate handles add and update events for remote ILB services.
//
// ILB services are created with a ServiceID that includes the cluster name.
// From the perspective of the cluster importing ILB services, each incoming ILB
// service is a unique mapping of frontend endpoint to backend endpoints, even
// when they have the same name and namespace. This is unlike the typical
// cluster mesh implementation where global services that share the same name
// will share the same pool of backends.
//
// In other words, multiple clusters can host ILB services with the same name
// and namespace combination, but they are independent and each needs to be
// accessed through its own service IP. There is no load balancing across
// multiple clusters through this feature.
//
// This path is intended to be taken *instead of* the typical service creation
// path. It updates the local service caches and enqueues an event to update the
// ebpf maps.
//
// Even though this function (and ilbExternalDelete) exists in the same codepath
// used by the operator and the daemon, it will only ever be called in the
// daemon, since the operator does not watch remote cluster kvstores. Therefore,
// external ILBs will not be stored in the local cluster's kvstore.
func (s *ServiceCache) ilbExternalUpdate(service *serviceStore.ClusterService, swg *lock.StoppableWaitGroup) {
	id := ServiceID{Name: generateClusterServiceName(service), Namespace: service.Namespace}
	scopedLog := log.WithFields(logrus.Fields{
		logfields.K8sSvcName:   id.Name,
		logfields.K8sNamespace: id.Namespace,
		logfields.ClusterName:  service.Cluster,
	})
	scopedLog.Debug("Processing remote ILB service update")

	svc, endpoints := ilbConvertService(service)
	scopedLog = scopedLog.WithField("backends", endpoints.Backends)
	if _, existedBefore := s.services[id]; !existedBefore {
		scopedLog.Info("Creating new ILB service")
	}

	if len(endpoints.Backends) == 0 {
		scopedLog.Warning("ILB service has no backends.")
	}

	// Update local caches.
	s.services[id] = svc
	externalEndpoints, ok := s.externalEndpoints[id]
	if !ok {
		s.externalEndpoints[id] = newExternalEndpoints()
	}
	if cachedEndpoints := externalEndpoints.endpoints[service.Cluster]; !reflect.DeepEqual(cachedEndpoints, endpoints) {
		if cachedEndpoints == nil {
			cachedEndpoints = newEndpoints()
		}
		scopedLog.WithField("previousBackends", cachedEndpoints.Backends).Debug("Updating cached backends on ILB service.")
	} else {
		scopedLog.Debug("Endpoints on ILB service did not change.")
	}
	// The endpoints map here will only ever have one entry in it, since the ID
	// is unique per cluster.
	s.externalEndpoints[id].endpoints[service.Cluster] = endpoints

	// Update bpf maps.
	swg.Add()
	s.emitEvent(ServiceEvent{
		Action:    UpdateService,
		ID:        id,
		Service:   svc,
		Endpoints: endpoints,
		SWG:       swg,
	})
}

// ilbExternalDelete handles delete events for remote ILB services.
//
// This path is intended to be taken *instead of* the typical service deletion
// path. It updates the local service caches and enqueues an event to update the
// ebpf maps.
//
// See ilbExternalUpdate for more details.
func (s *ServiceCache) ilbExternalDelete(service *serviceStore.ClusterService, swg *lock.StoppableWaitGroup) {
	id := ServiceID{Name: generateClusterServiceName(service), Namespace: service.Namespace}
	log := log.WithFields(logrus.Fields{
		logfields.K8sSvcName:   id.Name,
		logfields.K8sNamespace: id.Namespace,
		logfields.ClusterName:  service.Cluster,
	})
	log.Debug("Processing remote ILB service delete")

	// Update local caches.
	_, existedBefore := s.services[id]
	delete(s.services, id)
	svc, endpoints := ilbConvertService(service)
	delete(s.externalEndpoints, id)

	if existedBefore {
		log.Info("Deleting ILB service")
	} else {
		log.Debug("ILB service delete was called for service that does not exist in the local service cache.")
	}

	// Update bpf maps.
	swg.Add()
	s.emitEvent(ServiceEvent{
		Action:    DeleteService,
		ID:        id,
		Service:   svc,
		Endpoints: endpoints,
		SWG:       swg,
	})
}

// ilbConvertService() converts the external ClusterService to a local Service
func ilbConvertService(externalService *serviceStore.ClusterService) (*Service, *Endpoints) {
	id := ServiceID{Name: externalService.Name, Namespace: externalService.Namespace}
	scopedLog := log.WithFields(logrus.Fields{
		logfields.K8sSvcName:   id.Name,
		logfields.K8sNamespace: id.Namespace,
		logfields.ClusterName:  externalService.Cluster,
	})

	// There should not be more than 1 FrontendIP.  If for some reason we get here we will
	// always pick the first one in the map, which does not have a guaranteed order.
	if len(externalService.Frontends) != 1 {
		scopedLog.Warningf("Unexpected number of frontend IPs in remote ILB service: %v", externalService.Frontends)
	}

	var ip net.IP
	var svcport serviceStore.PortConfiguration
	for vip, port := range externalService.Frontends {
		ip = net.ParseIP(vip)
		svcport = port
		break
	}
	var ips []net.IP
	if ip != nil {
		ips = append(ips, ip)
	}

	// This service represents a local version of the external service.
	// This overrides a few service fields that are unsupported/irrelevant for this use case.  Also, the remote service must
	// be type:LoadBalancer but the local copy must use type:ClusterIP
	svc := NewService(ips, []string{}, []string{},
		[]string{}, false, loadbalancer.SVCTrafficPolicyCluster, loadbalancer.SVCTrafficPolicyCluster,
		0, externalService.Labels, make(map[string]string),
		externalService.Namespace, loadbalancer.SVCTypeClusterIP)

	for name, portSpec := range svcport {
		svc.Ports[loadbalancer.FEPortName(name)] = portSpec
	}

	// Populate from service. We don't need to merge from any other services
	// because ILB services are considered separate per cluster.
	endpoints := newEndpoints()
	for ip, port := range externalService.Backends {
		endpoints.Backends[cmtypes.MustParseAddrCluster(ip)] = &Backend{Ports: port}
	}

	scopedLog.Debugf("Converted remote ILB service: %+v, Endpoints: %+v", svc, endpoints)
	return svc, endpoints
}

// isIlbService checks if the local service should be exposed to remote clusters.
func isIlbService(svc *slimv1.Service) bool {
	if svc == nil {
		return false
	}

	return svc.Spec.Type == slimv1.ServiceTypeLoadBalancer && hasGlobalILBAnnotation(svc.Annotations) && len(svc.Status.LoadBalancer.Ingress) == 1
}

// isLocalIlbClusterService checks if the external ClusterService should be exposed to pods on the local cluster
// This func only works if the info was injected before the ClusterService was updated in etcd
func isLocalIlbClusterService(svc *serviceStore.ClusterService) bool {
	if svc == nil {
		return false
	}
	// If this is a global service then need to merge the service with existing
	// ones. So, ignore such services here.
	if svc.IncludeExternal {
		return false
	}

	return hasGlobalILBAnnotation(svc.Labels) && svc.Labels[serviceTypeKey] == string(slimv1.ServiceTypeLoadBalancer)
}

// isGlobalILBService checks if the local service should be exposed to remote clusters.
// This func only works if the info was injected before the Service was updated in etcd
func isGlobalILBService(svc *slimv1.Service) bool {
	if svc == nil {
		return false
	}
	// Global ILB services have the following properties:
	// - Type: LoadBalancer
	// - networking.gke.io/load-balancer-type: internal
	// - networking.gke.io/global-service: true
	// - 1 Ingress

	ilbAnnotation := hasGlobalILBAnnotation(svc.Annotations)

	return svc.Spec.Type == slimv1.ServiceTypeLoadBalancer && svc.Annotations[annotation.GlobalService] == globalServiceTrue && ilbAnnotation && len(svc.Status.LoadBalancer.Ingress) == 1
}

func isGlobalILBClusterService(svc *serviceStore.ClusterService) bool {
	if svc == nil {
		return false
	}
	if !svc.IncludeExternal {
		return false
	}
	return hasGlobalILBAnnotation(svc.Labels) && svc.Labels[serviceTypeKey] == string(slimv1.ServiceTypeLoadBalancer)
}

func (s *ServiceCache) globalILBUpdateLocal(svcID ServiceID) {
	scopedLog := log.WithFields(logrus.Fields{
		logfields.K8sSvcName:   svcID.Name,
		logfields.K8sNamespace: svcID.Namespace,
	})

	scopedLog.Debug("Processing local global ILB service update")
	if s.serviceTracker[svcID] == nil {
		s.serviceTracker[svcID] = map[string]bool{}
	}
	s.serviceTracker[svcID][option.Config.ClusterName] = true
}

func (s *ServiceCache) deleteGlobalILBServiceLocal(svcID ServiceID, swg *lock.StoppableWaitGroup) {
	scopedLog := log.WithFields(logrus.Fields{
		logfields.K8sSvcName:   svcID.Name,
		logfields.K8sNamespace: svcID.Namespace,
	})

	if s.serviceTracker[svcID] != nil {
		delete(s.serviceTracker[svcID], option.Config.ClusterName)
	}

	// If we are not the last service, do nothing. EndpointSlice update will take care of removing local endpoints.
	if len(s.serviceTracker[svcID]) != 0 {
		scopedLog.Debug("Processing local global ILB service delete, not the last service, skipping")
		return
	}
	scopedLog.Debug("Processing local global ILB service delete, last service, deleting")
	// Delete as normal if last service
	oldService, serviceOK := s.services[svcID]
	endpoints, _ := s.correlateEndpoints(svcID)
	delete(s.services, svcID)

	if serviceOK {
		swg.Add()
		s.sendEvents <- ServiceEvent{ // TODO: review here
			Action:    DeleteService,
			ID:        svcID,
			Service:   oldService,
			Endpoints: endpoints,
			SWG:       swg,
		}
	}
}

// globalILBConvertService creates a service from an external service in the case there are no local services.
// This is just a stand in for a real service in the case that no service exists in the local cluster.
func globalILBConvertService(externalService *serviceStore.ClusterService) *Service {
	id := ServiceID{Name: externalService.Name, Namespace: externalService.Namespace}
	scopedLog := log.WithFields(logrus.Fields{
		logfields.K8sSvcName:   id.Name,
		logfields.K8sNamespace: id.Namespace,
		logfields.ClusterName:  externalService.Cluster,
	})

	svc, _ := ilbConvertService(externalService)

	svc.IncludeExternal = true
	svc.Shared = true

	scopedLog.Debugf("Converted remote global ILB service: %+v", svc)
	return svc
}

func (s *ServiceCache) globalILBUpdateExternal(svc *serviceStore.ClusterService) {
	svcID := ServiceID{Name: svc.Name, Namespace: svc.Namespace}
	scopedLog := log.WithFields(logrus.Fields{
		logfields.K8sSvcName:   svcID.Name,
		logfields.K8sNamespace: svcID.Namespace,
		logfields.ClusterName:  svc.Cluster,
	})

	scopedLog.Debugf("External global ILB update, %+v", svc)

	if len(s.serviceTracker[svcID]) == 0 {
		s.serviceTracker[svcID] = map[string]bool{}
	}
	s.serviceTracker[svcID][svc.Cluster] = true
	if s.services[svcID] == nil {
		fakeService := globalILBConvertService(svc)
		s.services[svcID] = fakeService
	}
}

func (s *ServiceCache) globalILBDeleteExternal(svc *serviceStore.ClusterService) {
	svcID := ServiceID{Name: svc.Name, Namespace: svc.Namespace}
	scopedLog := log.WithFields(logrus.Fields{
		logfields.K8sSvcName:   svcID.Name,
		logfields.K8sNamespace: svcID.Namespace,
		logfields.ClusterName:  svc.Cluster,
	})

	scopedLog.Debugf("External global ILB delete, %+v", svc)

	if s.serviceTracker[svcID] == nil {
		return
	}
	delete(s.serviceTracker[svcID], svc.Cluster)
	if len(s.serviceTracker[svcID]) == 0 {
		delete(s.serviceTracker, svcID)
	}
}

// injectIlbInfo injects the info we need from the kubernetes service into the labels of the internal representation
// This is done by the clustermesh-apiserver when writing this info to etcd
// This func should only be used if the svc is an ilb service.
func injectIlbInfo(svc *slimv1.Service, internalService *Service, useFEIP bool) {
	if svc == nil || internalService == nil {
		return
	}

	log.WithFields(logrus.Fields{
		logfields.K8sSvcName:   svc.Name,
		logfields.K8sNamespace: svc.Namespace,
		"frontends":            internalService.FrontendIPs,
		"useFEIP":              useFEIP,
		"ingress":              svc.Status.LoadBalancer.Ingress,
	}).Debug("Injecting ILB info into service labels")
	if internalService.Labels == nil {
		internalService.Labels = map[string]string{}
	}

	// In GDC-H, it is possible that `ClusterIP` is different from LoadBalancerIP,
	// in which case we use the useFEIP flag to instead use the LB VIP as the
	// frontend. This is only required from the Clustermesh APIServer since it
	// advertises what other clusters should use to access the service.
	if len(svc.Status.LoadBalancer.Ingress) > 0 && useFEIP {
		lbVIP := svc.Status.LoadBalancer.Ingress[0].IP
		internalService.FrontendIPs = []net.IP{net.ParseIP(lbVIP)}
	}

	// Inject into labels to avoid modifying the k8s.Service representation
	// This info is propagated to the ClusterService before it is added to etcd
	internalService.Labels[serviceAnnotationKey] = serviceAnnotationValue
	internalService.Labels[serviceTypeKey] = string(svc.Spec.Type)
}

// injectGlobalILBInfo injects the LB VIP as the frontend IP of the service
// This is done by the clustermesh-apiserver when writing this info to etcd
// This func should only be used if the svc is a global ilb service.
func injectGlobalILBInfo(svc *slimv1.Service, internalService *Service) {
	if svc == nil || internalService == nil {
		return
	}
	if len(svc.Status.LoadBalancer.Ingress) == 0 {
		return
	}
	lbVIP := svc.Status.LoadBalancer.Ingress[0].IP
	internalService.FrontendIPs = []net.IP{net.ParseIP(lbVIP)}
	log.WithFields(logrus.Fields{
		logfields.K8sSvcName:   svc.Name,
		logfields.K8sNamespace: svc.Namespace,
	}).Debugf("Injecting Global ILB Endpoint as Frontend, Backend: %s", lbVIP)
}

func hasGlobalILBAnnotation(data map[string]string) bool {
	return (data[serviceAnnotationKey] == serviceAnnotationValue) || (data[serviceAnnotationKey] == globalServiceAnnotationValue)
}

func (s *ServiceCache) serviceAliasingUpdate(svcID *ServiceID, endpoints *Endpoints) error {
	if !s.GoogleConfig.EnableServiceAliasing {
		return nil
	}

	s.serviceAliasMapMutex.Lock()
	defer s.serviceAliasMapMutex.Unlock()
	if aliasID, ok := s.serviceAliasMap[*svcID]; ok {
		// Only do port renaming for service aliased services.
		s.renamePorts(svcID, endpoints)

		svcID.Name = aliasID.Name
		svcID.Namespace = aliasID.Namespace
		return nil
	}
	return fmt.Errorf("alias not found for service: %v", svcID)
}

func (s *ServiceCache) serviceAliasingDelete(svcID *ServiceID) error {
	if !s.GoogleConfig.EnableServiceAliasing {
		return nil
	}

	s.serviceAliasMapMutex.Lock()
	defer s.serviceAliasMapMutex.Unlock()
	if aliasID, ok := s.serviceAliasMap[*svcID]; ok {
		// cleanup renamePortMap
		delete(s.renamePortMap, aliasID)

		svcID.Name = aliasID.Name
		svcID.Namespace = aliasID.Namespace
		delete(s.serviceAliasMap, aliasID)
		return nil
	}
	return fmt.Errorf("alias not found for service: %v", svcID)
}

func (s *ServiceCache) parseServiceAlias(svc *slimv1.Service, swg *lock.StoppableWaitGroup) {
	if !s.GoogleConfig.EnableServiceAliasing {
		return
	}

	scopedLog := log.WithFields(logrus.Fields{
		"service": svc,
	})
	svcID := ServiceID{Name: svc.Name, Namespace: svc.Namespace}
	oldAlias, hasOldAlias := s.serviceAliasMap[svcID]

	newAliasName, hasNewAliasName := svc.Annotations[s.GoogleConfig.ServiceAliasNameAnnotation]
	hasNewAlias := hasNewAliasName && newAliasName != "" && s.GoogleConfig.ServiceAliasNamespace != ""

	var newAlias ServiceID
	if hasNewAlias {
		newAlias = ServiceID{Name: newAliasName, Namespace: s.GoogleConfig.ServiceAliasNamespace}

		// Only do port renaming for service aliased services.
		s.parsePortMap(svc)
		// Only mark service as global for service aliased services.
		markLBServiceGlobal(svc)
	}
	scopedLog = scopedLog.WithFields(logrus.Fields{
		"original_service": svcID,
		"old_alias":        oldAlias,
		"new_alias":        newAlias,
	})

	if (!hasNewAlias && !hasOldAlias) || (oldAlias == newAlias) {
		return
	}
	// If there is a change in alias, we need to send a delete event for the older service.
	// We do this before making changes to the s.serviceAliasMap
	s.DeleteService(svc, swg)

	s.serviceAliasMapMutex.Lock()
	defer s.serviceAliasMapMutex.Unlock()

	if hasOldAlias {
		delete(s.serviceAliasMap, svcID)
		if !hasNewAlias {
			// cleanup renamePortMap
			delete(s.renamePortMap, svcID)
		}
	}

	if hasNewAlias {
		s.serviceAliasMap[svcID] = newAlias
	}
}

func (s *ServiceCache) parsePortMap(svc *slimv1.Service) {
	svcID := ServiceID{Name: svc.Name, Namespace: svc.Namespace}
	portMap := map[string]string{}
	for _, port := range svc.Spec.Ports {
		portMap[port.Name] = fmt.Sprintf("%s-%d", strings.ToLower(string(port.Protocol)), port.Port)
	}
	s.renamePortMap[svcID] = portMap
}

func (s *ServiceCache) renamePorts(svcID *ServiceID, endpoints *Endpoints) {
	svc, ok := s.services[*svcID]
	if !ok {
		return
	}

	renamePortMap, ok := s.renamePortMap[*svcID]
	if !ok {
		return
	}

	// For GDC-AG ForwardingRules:
	// Change both svc and endpoint port names to match`protocol-port`
	// pattern. This will enable service merging in remote clusters.
	portMap := map[loadbalancer.FEPortName]*loadbalancer.L4Addr{}
	for name, port := range svc.Ports {
		if newName, ok := renamePortMap[string(name)]; ok {
			portMap[loadbalancer.FEPortName(newName)] = port
		} else {
			portMap[name] = port
		}
	}
	svc.Ports = portMap

	for _, backend := range endpoints.Backends {
		newPortConfig := map[string]*loadbalancer.L4Addr{}
		for oldPortName := range backend.Ports {
			if newPortName, ok := renamePortMap[oldPortName]; ok {
				newPortConfig[newPortName] = backend.Ports[oldPortName]
			}
		}
		backend.Ports = newPortConfig
	}
}

func markLBServiceGlobal(svc *slimv1.Service) {
	if svc.Spec.Type == slimv1.ServiceTypeLoadBalancer {

		// add cilium global annotation
		if svc.Annotations == nil {
			svc.Annotations = make(map[string]string)
		}
		svc.Annotations[annotation.GlobalService] = globalServiceTrue
	}
}
