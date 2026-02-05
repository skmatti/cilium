// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Authors of Cilium
package controller

import (
	"context"
	"fmt"
	"strings"
	"sync"

	networkv1client "github.com/GoogleCloudPlatform/gke-networking-api/client/network/clientset/versioned"
	operatorK8s "github.com/cilium/cilium/operator/k8s"
	"github.com/cilium/cilium/operator/pkg/flowtrace/logging"
	"github.com/cilium/cilium/operator/pkg/flowtrace/queue"
	ftv1 "github.com/cilium/cilium/pkg/gke/apis/flowtrace/v1alpha1"
	ftclientset "github.com/cilium/cilium/pkg/gke/client/flowtrace/clientset/versioned"
	ftInformer "github.com/cilium/cilium/pkg/gke/client/flowtrace/informers/externalversions"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/scheme"
	"github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/labels"
	v1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	v1core "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/record"
	"k8s.io/klog/v2"
)

// Controller is the controller for the FlowTrace CRD.
type Controller struct {
	ftInformer       cache.SharedIndexInformer
	eventRecorder    record.EventRecorder
	ftReconcileQueue *queue.FtReconcileQueue
	stopCh           chan struct{}
	stopOnce         sync.Once
	opResources      operatorK8s.Resources
	clientset        k8sClient.Clientset
	// GKE Network Interface client
	networkClient networkv1client.Interface
	// GKE FlowTrace client
	ftClient ftclientset.Interface
}

// NewController returns a new FlowTrace controller.
func NewController(clientset k8sClient.Clientset, opResources operatorK8s.Resources, networkClient networkv1client.Interface, flowtraceClient ftclientset.Interface) *Controller {
	broadcaster := record.NewBroadcaster()
	broadcaster.StartLogging(klog.Infof)
	broadcaster.StartRecordingToSink(&v1core.EventSinkImpl{Interface: clientset.CoreV1().Events("")})
	recorder := broadcaster.NewRecorder(scheme.Scheme, v1.EventSource{Component: controllerName})
	informerFactory := ftInformer.NewSharedInformerFactory(flowtraceClient, informerSyncPeriod)
	c := &Controller{
		ftInformer:    informerFactory.Networking().V1alpha1().FlowTraces().Informer(),
		eventRecorder: recorder,
		stopCh:        make(chan struct{}),
		stopOnce:      sync.Once{},
		opResources:   opResources,
		clientset:     clientset,
		networkClient: networkClient,
		ftClient:      flowtraceClient,
	}
	c.ftReconcileQueue = queue.NewFtReconcileQueue(controllerName, c.sync)
	c.ftInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			key, err := cache.MetaNamespaceKeyFunc(obj)
			if err != nil {
				logging.FtLogger.Errorf("Couldn't get key for object %+v", obj)
				return
			}
			c.ftReconcileQueue.Enqueue(queue.FtKey{Key: key, Operation: queue.CREATE})
		},
		UpdateFunc: func(old, new interface{}) {
			oldFT := old.(*ftv1.FlowTrace)
			newFT := new.(*ftv1.FlowTrace)

			// Only reconcile when the source node is unassigned this will be triggered when source pod reschedules.
			if !(oldFT.Status.SourceNode != "" && newFT.Status.SourceNode == "") {
				return
			}

			key, err := cache.MetaNamespaceKeyFunc(new)
			if err != nil {
				logging.FtLogger.WithError(err).Errorf("Couldn't get key for object %+v", new)
				return
			}
			c.ftReconcileQueue.Enqueue(queue.FtKey{Key: key, OldFt: old, Operation: queue.UPDATE})
		},
	})
	return c
}

// Start runs the controller.
func (c *Controller) Start(ctx context.Context) {
	logging.FtLogger.Info("Starting FlowTrace controller")
	go c.ftInformer.Run(c.stopCh)
	if !cache.WaitForNamedCacheSync(controllerName, ctx.Done(), c.ftInformer.HasSynced) {
		logging.FtLogger.Error("Failed to wait for caches to sync")
		return
	}
	go c.ftReconcileQueue.Run()
}

// Stop terminates the controller gracefully.
func (c *Controller) Stop() {
	c.stopOnce.Do(func() {
		logging.FtLogger.Info("Stopping FlowTrace controller")
		close(c.stopCh)
		c.ftReconcileQueue.Shutdown()
	})
}
func (c *Controller) sync(ctx context.Context, key queue.FtKey) error {
	scopedLog := logging.FtLogger.WithField(loggerFieldKey, key)
	if !cache.WaitForNamedCacheSync(controllerName, c.stopCh, c.ftInformer.HasSynced) {
		err := fmt.Errorf("failed to wait for FlowTrace informer cache to sync")
		scopedLog.Error(err.Error())
		return err
	}
	scopedLog.Info("Syncing FlowTrace")
	obj, exists, err := c.ftInformer.GetStore().GetByKey(key.Key)
	if err != nil {
		scopedLog.WithError(err).Warnf("Error getting FlowTrace with key %s", key.Key)
		return fmt.Errorf("error getting FlowTrace for key %s: %v", key.Key, err)
	}
	if !exists {
		scopedLog.Warnf("FlowTrace does not exist with key: %s", key.Key)
		return nil
	}
	ft, ok := obj.(*ftv1.FlowTrace)
	if !ok {
		return fmt.Errorf("unexpected object type: %T", obj)
	}
	switch key.Operation {
	case queue.CREATE, queue.UPDATE:
		return c.createOrUpdateHandler(ctx, ft)
	default:
		scopedLog.Errorf("Unknown operation %v for key %s", key.Operation, key.Key)
	}
	return nil
}

// createOrUpdateHandler handles create and update events for FlowTrace.
func (c *Controller) createOrUpdateHandler(ctx context.Context, ft *ftv1.FlowTrace) error {
	logging.FtLogger.Infof("Processing FlowTrace CREATE/UPDATE event: %s, Spec: %+v", ft.Name, ft.Spec)
	var sourceNodeName string
	var err error
	if ft.Spec.SourceEndpoint.IP != "" {
		sourceIPStr := ft.Spec.SourceEndpoint.IP
		sourceNodeName, err = c.getNodeNameByIP(ctx, sourceIPStr)
		if err != nil {
			logging.FtLogger.Errorf("Error getting source node name for %s with IP %s: %v", ft.Name, sourceIPStr, err)
			c.eventRecorder.Eventf(ft, v1.EventTypeWarning, "SourceResolutionFailed", "Failed to resolve source node for IP: %v", err)
			return err
		}
	} else if podKey := ft.Spec.SourceEndpoint.K8sPodKey; podKey.Name != "" && podKey.Namespace != "" {
		sourceNodeName, err = c.resolveNodeNameByPodKey(ctx, podKey.Namespace, podKey.Name)
		if err != nil {
			logging.FtLogger.Errorf("Error getting source node name for %s with PodKey %s/%s: %v", ft.Name, podKey.Namespace, podKey.Name, err)
			c.eventRecorder.Eventf(ft, v1.EventTypeWarning, "SourceResolutionFailed", "Failed to resolve source node for PodKey: %v", err)
			return err
		}
	} else {
		err = fmt.Errorf("source IP or K8sPodKey must be provided in spec")
		logging.FtLogger.Errorf("Error for %s: %v", ft.Name, err)
		c.eventRecorder.Eventf(ft, v1.EventTypeWarning, "SourceResolutionFailed", err.Error())
		return nil
	}
	logging.FtLogger.Infof("Determined source node for %s: %s", ft.Name, sourceNodeName)

	// Get the latest version from the API server to minimize conflicts
	latestFT, err := c.ftClient.NetworkingV1alpha1().FlowTraces().Get(ctx, ft.Name, metav1.GetOptions{})
	if err != nil {
		c.eventRecorder.Eventf(ft, v1.EventTypeWarning, "StatusUpdateFailed", "Failed to get latest FT %s: %v", ft.Name, err)
		return fmt.Errorf("failed to get latest FT %s: %w", ft.Name, err)
	}
	ftToUpdate := latestFT.DeepCopy()
	ftToUpdate.Status.SourceNode = sourceNodeName
	if _, err := c.ftClient.NetworkingV1alpha1().FlowTraces().UpdateStatus(ctx, ftToUpdate, metav1.UpdateOptions{}); err != nil {
		c.eventRecorder.Eventf(ft, v1.EventTypeWarning, "StatusUpdateFailed", "Failed to update status for %s: %v", ft.Name, err)
		return err
	}
	c.eventRecorder.Eventf(ft, v1.EventTypeNormal, "Processed", "Successfully processed FlowTrace %s", ft.Name)
	return nil
}

func (c *Controller) resolveNodeNameByPodKey(ctx context.Context, namespace, name string) (string, error) {
	podKeyStr := fmt.Sprintf("%s/%s", namespace, name)
	pod, err := c.clientset.CoreV1().Pods(namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			return "", fmt.Errorf("pod %s not found", podKeyStr)
		}
		return "", fmt.Errorf("failed to get pod %s: %w", podKeyStr, err)
	}
	if pod.Spec.NodeName == "" {
		return "", fmt.Errorf("node name not set for pod %s", podKeyStr)
	}
	return pod.Spec.NodeName, nil
}

func (c *Controller) getNodeNameByIP(ctx context.Context, ip string) (string, error) {
	// 1. Check Pod IP
	nodeName, err := c.findNodeByPodIP(ctx, ip)
	if err != nil {
		return "", err
	} else if nodeName != "" {
		return nodeName, nil
	}

	// 2. Check Node IP
	logging.FtLogger.Infof("No pods found with IP %s. Checking Nodes...", ip)
	nodeName, err = c.findNodeByNodeIP(ctx, ip)
	if err != nil {
		return "", err
	} else if nodeName != "" {
		return nodeName, nil
	}

	// 3. Check multiNIC endpoints
	logging.FtLogger.Infof("No Node found directly with IP %s, searching for multinic endpoints", ip)
	nodeName, err = c.findNodeByNetworkInterfaceIP(ctx, ip)
	if err != nil {
		return "", err
	} else if nodeName != "" {
		return nodeName, nil
	}

	return "", fmt.Errorf("no pod or node found with IP %s", ip)
}

func (c *Controller) findNodeByPodIP(ctx context.Context, ip string) (string, error) {
	listOptions := metav1.ListOptions{
		FieldSelector: fmt.Sprintf("status.podIP=%s", ip),
	}
	pods, err := c.clientset.CoreV1().Pods("").List(ctx, listOptions)
	if err != nil {
		return "", fmt.Errorf("failed to list pods with IP %s: %w", ip, err)
	}
	for i := range pods.Items {
		pod := &pods.Items[i]
		if pod.Status.PodIP == ip {
			if pod.Spec.NodeName == "" {
				return "", fmt.Errorf("pod %s/%s has IP %s but NodeName is not set", pod.Namespace, pod.Name, ip)
			}
			return pod.Spec.NodeName, nil
		}
	}
	return "", nil
}

func (c *Controller) findNodeByNodeIP(ctx context.Context, ip string) (string, error) {
	nodes, err := c.clientset.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return "", fmt.Errorf("failed to list nodes for IP %s: %w", ip, err)
	}
	for _, node := range nodes.Items {
		for _, addr := range node.Status.Addresses {
			if addr.Address == ip {
				logging.FtLogger.Infof("Found IP %s on Node %s", ip, node.Name)
				return node.Name, nil
			}
		}
	}
	return "", nil
}

func (c *Controller) findNodeByNetworkInterfaceIP(ctx context.Context, ip string) (string, error) {
	niList, err := c.networkClient.NetworkingV1().NetworkInterfaces("").List(ctx, metav1.ListOptions{LabelSelector: labels.Everything().String()})
	if err != nil {
		return "", fmt.Errorf("failed to list NetworkInterfaces for IP %s fallback: %w", ip, err)
	}
	for _, ni := range niList.Items {
		for _, niIP := range ni.Status.IpAddresses {
			ipOnly := strings.Split(niIP, "/")[0]
			if ipOnly == ip {
				if ni.Status.PodName == nil || *ni.Status.PodName == "" {
					continue
				}
				podName := *ni.Status.PodName
				podNamespace := ni.Namespace
				pod, err := c.clientset.CoreV1().Pods(podNamespace).Get(ctx, podName, metav1.GetOptions{})
				if err != nil {
					return "", fmt.Errorf("failed to get pod %s/%s from NetworkInterface for IP %s: %w", podNamespace, podName, ip, err)
				}
				if pod.Spec.NodeName == "" {
					return "", fmt.Errorf("pod %s/%s from NetworkInterface for IP %s has no NodeName", podNamespace, podName, ip)
				}
				return pod.Spec.NodeName, nil
			}
		}
	}
	return "", nil
}
