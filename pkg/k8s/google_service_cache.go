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
This file contains the logic for ILB services running in GDC-H.  It extends the service cache
logic which is used by both cilium-agent (anetd) and clustermesh-apiserver.
*/

package k8s

import (
	"fmt"
	"net"

	slimv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	serviceStore "github.com/cilium/cilium/pkg/service/store"
	"github.com/sirupsen/logrus"
)

const (
	serviceAnnotationKey   = "networking.gke.io/load-balancer-type"
	serviceAnnotationValue = "internal"
	serviceTypeKey         = "serviceType"
)

// generateServiceName creates a unique service name by using the cluster name as a prefix.
// Using a different internal name for the service allows us to avoid conflicts with local services with the same namespace/name.
func generateClusterServiceName(service *serviceStore.ClusterService) string {
	return fmt.Sprintf("%s-%s", service.Cluster, service.Name)
}

// ilbExternalUpdate handles add and update events for ILB services
func (s *ServiceCache) ilbExternalUpdate(service *serviceStore.ClusterService, swg *lock.StoppableWaitGroup) {
	action := UpdateService
	id := ServiceID{Name: generateClusterServiceName(service), Namespace: service.Namespace}
	scopedLog := log.WithFields(logrus.Fields{
		logfields.K8sSvcName:   id.Name,
		logfields.K8sNamespace: id.Namespace,
		logfields.ClusterName:  service.Cluster,
	})
	scopedLog.Debug("Processing service update")

	svc, endpoints := s.ilbConvertService(service)
	// Check to see if it was previously an ILB service, so we can GC it.
	// If there are previous backends then we have synced this to the bpf map before.
	if !isIlbClusterService(service) {
		if len(endpoints.Backends) == 0 {
			scopedLog.Debug("Will not process, service is not an ILB and has no Backends")
			return
		}
		action = DeleteService
		scopedLog.Infof("Removing enpdoints since service is no longer an ILB")
	}

	swg.Add()
	s.Events <- ServiceEvent{
		Action:    action,
		ID:        id,
		Service:   svc,
		Endpoints: endpoints,
		SWG:       swg,
	}
}

// ilbExternalDelete handles delete events for ILB services
func (s *ServiceCache) ilbExternalDelete(service *serviceStore.ClusterService, swg *lock.StoppableWaitGroup) {
	id := ServiceID{Name: generateClusterServiceName(service), Namespace: service.Namespace}
	svc, endpoints := s.ilbConvertService(service)

	log.WithFields(logrus.Fields{
		logfields.K8sSvcName:   id.Name,
		logfields.K8sNamespace: id.Namespace,
		logfields.ClusterName:  service.Cluster,
	}).Debug("Processing service delete")

	swg.Add()
	event := ServiceEvent{
		Action:    DeleteService,
		ID:        id,
		Service:   svc,
		Endpoints: endpoints,
		SWG:       swg,
	}
	s.Events <- event
}

// ilbConvertService() converts the external ClusterService to a local Service
func (s *ServiceCache) ilbConvertService(externalService *serviceStore.ClusterService) (*Service, *Endpoints) {
	id := ServiceID{Name: externalService.Name, Namespace: externalService.Namespace}
	scopedLog := log.WithFields(logrus.Fields{
		logfields.K8sSvcName:   id.Name,
		logfields.K8sNamespace: id.Namespace,
		logfields.ClusterName:  externalService.Cluster,
	})

	// There should not be more than 1 FrontendIP.  If for some reason we get here we will
	// always pick the first one in the map, which does not have a guaranteed order.
	if len(externalService.Frontends) != 1 {
		scopedLog.Warningf("Unexpected number of frontend IPs: %v", externalService.Frontends)
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
		[]string{}, false, loadbalancer.SVCTrafficPolicyCluster,
		0, externalService.Labels, make(map[string]string),
		externalService.Namespace, loadbalancer.SVCTypeClusterIP)

	for name, portSpec := range svcport {
		svc.Ports[loadbalancer.FEPortName(name)] = portSpec
	}
	endpoints := newEndpoints()
	exEndpoints := s.externalEndpoints[id]

	for clusterName, remoteClusterEndpoints := range exEndpoints.endpoints {
		// There shouldn't be another cluster service with the exact same name + namespace. But,
		// we want to filter that out just in case.
		if clusterName == externalService.Cluster {
			for ip, e := range remoteClusterEndpoints.Backends {
				endpoints.Backends[ip] = e
			}
		} else {
			scopedLog.Warningf("Duplicate service exists in cluster: %s, endpoint: %v", clusterName, remoteClusterEndpoints)
		}
	}

	scopedLog.Debugf("Service: %+v, Endpoints: %+v", svc, endpoints)
	return svc, endpoints
}

// isIlbService checks if the local service should be exposed to remote clusters.
func isIlbService(svc *slimv1.Service) bool {
	if svc == nil {
		return false
	}
	return svc.Spec.Type == slimv1.ServiceTypeLoadBalancer && svc.Annotations[serviceAnnotationKey] == serviceAnnotationValue && len(svc.Status.LoadBalancer.Ingress) == 1
}

// isIlbClusterService checks if the external ClusterService should be exposed to pods on the local cluster
// This func only works if the info was injected before the ClusterService was updated in etcd
func isIlbClusterService(svc *serviceStore.ClusterService) bool {
	if svc == nil {
		return false
	}
	return svc.Labels[serviceAnnotationKey] == serviceAnnotationValue && svc.Labels[serviceTypeKey] == string(slimv1.ServiceTypeLoadBalancer)
}

// injectIlbInfo injects the info we need from the kubernetes service into the labels of the internal representation
// This is done by the clustermesh-apiserver when writing this info to etcd
// This func should only be used if the svc is an ilb service.
func injectIlbInfo(svc *slimv1.Service, internalService *Service) {
	if svc == nil || internalService == nil {
		return
	}

	log.WithFields(logrus.Fields{
		logfields.K8sSvcName:   svc.Name,
		logfields.K8sNamespace: svc.Namespace,
	}).Debug("Injecting ILB info into service labels")

	if internalService.Labels == nil {
		internalService.Labels = map[string]string{}
	}

	// Inject into labels to avoid modifying the k8s.Service representation
	// This info is propagated to the ClusterService before it is added to etcd
	internalService.Labels[serviceAnnotationKey] = serviceAnnotationValue
	internalService.Labels[serviceTypeKey] = string(svc.Spec.Type)
}
