// Copyright 2020 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// This file keeps the logic for RedirectService CRD controller.
// It watches the RedirectService CRD and make the call
// to configure the loggers.
package controller

import (
	"fmt"
	"net"
	"time"

	"github.com/cilium/cilium/pkg/datapath/iptables"
	"github.com/cilium/cilium/pkg/gke/apis/redirectservice/v1alpha1"
	"github.com/cilium/cilium/pkg/gke/client/redirectservice/clientset/versioned"
	"github.com/cilium/cilium/pkg/gke/client/redirectservice/clientset/versioned/scheme"
	"github.com/cilium/cilium/pkg/gke/client/redirectservice/informers/externalversions"
	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/k8s/informer"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/redirectpolicy"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/client-go/kubernetes"
	v1core "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/record"
	"k8s.io/klog/v2"
)

type redirectServiceType int

const (
	redirectServiceTypeNone redirectServiceType = iota
	redirectServiceTypeNodeLocalDNS
)

var (
	log = logging.DefaultLogger.WithField(logfields.LogSubsys, "gke-redirect-service-controller")
)

const (
	// informerSyncPeriod is the period to sync with API server
	informerSyncPeriod = 15 * time.Minute

	// This is the only accepted name for RedirectService CR.
	redirectServiceResourceName = "default"
)

type RedirectPolicyManager interface {
	AddRedirectPolicy(config redirectpolicy.LRPConfig) (bool, error)
	DeleteRedirectPolicy(config redirectpolicy.LRPConfig) error
	GetLocalPodsForPolicy(config *redirectpolicy.LRPConfig) []string
}

// Controller for the redirect service controller
type Controller struct {
	// kubeClient will be used to generate the recorder for events.
	kubeClient kubernetes.Interface

	redirectServiceClient   versioned.Interface
	redirectServiceInformer cache.SharedIndexInformer
	eventBroadcaster        record.EventBroadcaster
	eventRecorder           record.EventRecorder

	redirectPolicyManager RedirectPolicyManager
	iptablesManager       *iptables.IptablesManager
	podController         cache.Controller

	stopCh chan struct{}
	mutex  lock.Mutex

	manageNoTrackRules bool
}

// NewController returns a new controller for redirect service.
func NewController(kubeClient kubernetes.Interface, redirectServiceClient versioned.Interface, watcherClient k8s.K8sClient, redirectPolicyManager RedirectPolicyManager) (*Controller, error) {

	broadcaster := record.NewBroadcaster()
	broadcaster.StartLogging(klog.Infof)
	broadcaster.StartRecordingToSink(&v1core.EventSinkImpl{Interface: kubeClient.CoreV1().Events("")})
	recorder := broadcaster.NewRecorder(scheme.Scheme, v1.EventSource{Component: "redirect-service-controller", Host: nodeTypes.GetName()})

	redirectServiceInformerFactory := externalversions.NewSharedInformerFactory(redirectServiceClient, informerSyncPeriod)

	c := &Controller{
		kubeClient:              kubeClient,
		redirectServiceClient:   redirectServiceClient,
		redirectServiceInformer: redirectServiceInformerFactory.Networking().V1alpha1().RedirectServices().Informer(),
		eventBroadcaster:        broadcaster,
		eventRecorder:           recorder,
		redirectPolicyManager:   redirectPolicyManager,
		stopCh:                  make(chan struct{}),
		iptablesManager:         &iptables.IptablesManager{},
	}

	c.iptablesManager.Init()

	c.redirectServiceInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    func(obj interface{}) { c.updateHandler(obj) },
		UpdateFunc: func(old, curr interface{}) { c.updateHandler(curr) },
		DeleteFunc: c.delHandler,
	})

	_, c.podController = informer.NewInformer(
		cache.NewListWatchFromClient(watcherClient.CoreV1().RESTClient(),
			"pods", "kube-system", fields.ParseSelectorOrDie("spec.nodeName="+nodeTypes.GetName())),
		&slim_corev1.Pod{},
		0,
		cache.ResourceEventHandlerFuncs{
			UpdateFunc: func(old, curr interface{}) { c.addNoTrackHandler(old, curr) },
			DeleteFunc: c.delNoTrackHandler,
		},
		nil,
	)

	return c, nil
}

// validateRedirect validates the redirect spec.
func validateRedirect(spec v1alpha1.RedirectSpec) error {
	if spec.Type == v1alpha1.NodeLocalDNSRedirectServiceType {
		if spec.Provider == v1alpha1.KubeDNSServiceProviderType || spec.Provider == v1alpha1.CloudDNSServiceProviderType {
			return nil
		}
		return fmt.Errorf("unsupported DNS provider %s", spec.Provider)
	}
	return fmt.Errorf("unsupported service type %s", spec.Type)
}

func getRedirectProvider(rs *v1alpha1.RedirectService) v1alpha1.ServiceProviderType {
	return rs.Spec.Redirect.Provider
}

// validateObj validates and converts an object to *v1alpha1.RedirectService.
func (c *Controller) validateObj(obj interface{}) (*v1alpha1.RedirectService, error) {
	rs, ok := obj.(*v1alpha1.RedirectService)
	if !ok {
		return nil, fmt.Errorf("invalid type %T", obj)
	}

	if rs.Name != redirectServiceResourceName {
		return rs, fmt.Errorf("invalid object name %s, expected %s", rs.Name, redirectServiceResourceName)
	}

	if err := validateRedirect(rs.Spec.Redirect); err != nil {
		return rs, fmt.Errorf("invalid redirect service spec %v", err)
	}

	return rs, nil
}

func (c *Controller) generateLRPConfig(rs *v1alpha1.RedirectService, rsType redirectServiceType) (*redirectpolicy.LRPConfig, error) {
	if rsType != redirectServiceTypeNodeLocalDNS {
		return nil, fmt.Errorf("unsupported redirect service type %v", rsType)
	}

	return redirectpolicy.ConstructNodeLocalDNSLRP(rs.Name, rs.Namespace, rs.GetUID()), nil
}

// addNoTrackHandler handles inserting NOTRACK rules at the first time IP addresses are allocated.
func (c *Controller) addNoTrackHandler(old, curr interface{}) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	if !c.manageNoTrackRules {
		return
	}

	if oldPod := k8s.ObjTov1Pod(old); oldPod != nil {
		if newPod := k8s.ObjTov1Pod(curr); newPod != nil {
			labels := newPod.ObjectMeta.Labels
			if val, found := labels[redirectpolicy.KeyNodeLocalDNS]; found && (val == redirectpolicy.LabelNodeLocalDNS || val == redirectpolicy.LabelNodeLocalDNSDPv2) {
				// pod.Status.PodIPs are supposed to be very short slices
				// add rules for newly assigned IPs
				for _, ip := range newPod.Status.PodIPs {
					exists := false
					for _, val := range oldPod.Status.PodIPs {
						if val == ip {
							exists = true
							break
						}
					}
					if !exists {
						c.addNoTrackRules(ip.IP)
					}
				}
				// remove rules for old IPs
				for _, ip := range oldPod.Status.PodIPs {
					exists := false
					for _, val := range newPod.Status.PodIPs {
						if val == ip {
							exists = true
							break
						}
					}
					if !exists {
						c.removeNoTrackRules(ip.IP)
					}
				}
			}
		}
	}
}

// updateHandler handles RedirectService CRD add and update events.
func (c *Controller) updateHandler(obj interface{}) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	o, err := c.validateObj(obj)
	if err != nil {
		// Note that when validation fails, although the CR is already in etcd, it doesn't
		// take effect and the system is still in the old state.
		log.Errorf("RedirectService obj %v is invalid, err %v", obj, err)
		c.eventRecorder.Eventf(o, v1.EventTypeWarning, InvalidRedirectService, err.Error())
		return
	}
	provider := getRedirectProvider(o)

	if provider == v1alpha1.KubeDNSServiceProviderType {
		c.installNodeLocalDNSRedirect(o)
	}

	if provider == v1alpha1.CloudDNSServiceProviderType {
		c.clearNodeLocalDNSRedirect(o)
	}
}

func (c *Controller) installNodeLocalDNSRedirect(o *v1alpha1.RedirectService) {
	c.manageNoTrackRules = true
	lrpConfig, err := c.generateLRPConfig(o, redirectServiceTypeNodeLocalDNS)
	if err != nil {
		log.Errorf("Generating LRP config error %v", err)
		return
	}

	_, err = c.redirectPolicyManager.AddRedirectPolicy(*lrpConfig)
	if err != nil {
		log.Errorf("Error adding LRP %v", err)
		return
	}

	c.eventRecorder.Eventf(o, v1.EventTypeNormal, UpdateRedirectService,
		fmt.Sprintf("Updating redirect service (resourceVersion = %s) ", o.ResourceVersion))
}

// delNoTrackHandler handles removing NOTRACK rules when nodelocaldns pod is removed.
func (c *Controller) delNoTrackHandler(obj interface{}) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	if !c.manageNoTrackRules {
		return
	}

	if pod := k8s.ObjTov1Pod(obj); pod != nil {
		labels := pod.ObjectMeta.Labels
		val, found := labels[redirectpolicy.KeyNodeLocalDNS]
		if found && (val == redirectpolicy.LabelNodeLocalDNS || val == redirectpolicy.LabelNodeLocalDNSDPv2) {
			for _, ip := range pod.Status.PodIPs {
				c.removeNoTrackRules(ip.IP)
			}
		}
	}
}
func (c *Controller) addNoTrackRules(ip string) {
	log.Debugf("Upserting NOTRACK rule for %v:%v", ip, redirectpolicy.PortNodeLocalDNS)
	ipv6 := net.ParseIP(ip).To4() == nil
	if err := c.iptablesManager.InstallNoTrackRules(ip, redirectpolicy.PortNodeLocalDNS, ipv6); err != nil {
		log.Warnf("Error upserting NOTRACK rules %v", err)
	}
}

func (c *Controller) removeNoTrackRules(ip string) {
	ipv6 := net.ParseIP(ip).To4() == nil
	log.Debugf("Removing NOTRACK rules for %v:%v", ip, redirectpolicy.PortNodeLocalDNS)
	if err := c.iptablesManager.RemoveNoTrackRules(ip, redirectpolicy.PortNodeLocalDNS, ipv6); err != nil {
		log.Warnf("Error removing NOTRACK rules %v", err)
	}
}

// delHandler handles RedirectService CRD delete events.
func (c *Controller) delHandler(obj interface{}) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	o, ok := obj.(*v1alpha1.RedirectService)
	if !ok {
		deletedObj, deletedOk := obj.(cache.DeletedFinalStateUnknown)
		if deletedOk {
			o, ok = deletedObj.Obj.(*v1alpha1.RedirectService)
		}
		if !ok {
			log.Warningf("Cannot recover the deleted redirect service obj %v", obj)
			return
		}
	}
	// Only do name check and skip the spec check as this is for deletion.
	if o.Name != redirectServiceResourceName {
		return
	}

	c.clearNodeLocalDNSRedirect(o)
}

// clearNodeLocalDNSRedirect clears the LRP and NOTRACK rules for nodelocaldns+kubedns
func (c *Controller) clearNodeLocalDNSRedirect(o *v1alpha1.RedirectService) {
	c.manageNoTrackRules = false

	lrpConfig, err := c.generateLRPConfig(o, redirectServiceTypeNodeLocalDNS)
	if err != nil {
		log.Errorf("Generating LRP config error %v", err)
		return
	}

	for _, ip := range c.redirectPolicyManager.GetLocalPodsForPolicy(lrpConfig) {
		c.removeNoTrackRules(ip)
	}

	// DeleteRedirectPolicy will do nothing if lrpConfig does not exist
	err = c.redirectPolicyManager.DeleteRedirectPolicy(*lrpConfig)
	if err != nil {
		log.Errorf("Error deleting LRP %v", err)
		return
	}

	c.eventRecorder.Eventf(o, v1.EventTypeNormal, UpdateRedirectService,
		fmt.Sprintf("deleted redirect service obj %s", o.Name))
}

// run starts redirect service controller and wait for stop.
func (c *Controller) Run() {
	log.Info("Starting redirect service controller")
	go c.redirectServiceInformer.Run(c.stopCh)
	if ok := cache.WaitForNamedCacheSync("redirectservice", c.stopCh, c.redirectServiceInformer.HasSynced); !ok {
		log.Error("Failed to wait for redirectservice caches to sync")
		return
	}
	go c.podController.Run(c.stopCh)
	if ok := cache.WaitForNamedCacheSync("pods", c.stopCh, c.podController.HasSynced); !ok {
		log.Error("Failed to wait for pod caches to sync")
		return
	}
	<-c.stopCh
	log.Info("Shutting down redirect service controller")
	return
}

func Init(redirectPolicyManager RedirectPolicyManager) (*Controller, error) {
	kubeConfig, err := k8s.CreateConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to create k8s configuration: %v", err)
	}

	kubeClient, err := kubernetes.NewForConfig(kubeConfig)
	if err != nil {
		return nil, fmt.Errorf("Failed to create kube client: %v", err)
	}

	redirectServiceClient, err := versioned.NewForConfig(kubeConfig)
	if err != nil {
		return nil, fmt.Errorf("Failed to create redirect service client: %v", err)
	}

	redirectServiceController, err := NewController(kubeClient, redirectServiceClient, *k8s.WatcherClient(), redirectPolicyManager)
	if err != nil {
		log.Errorf("Error instantiating redirect service controller %v", err)
		return nil, err
	}
	go redirectServiceController.Run()
	return redirectServiceController, nil
}
