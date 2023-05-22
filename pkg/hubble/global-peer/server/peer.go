// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package server

import (
	"context"
	"fmt"
	"net"
	"time"

	peerpb "github.com/cilium/cilium/api/v1/peer"
	datapath "github.com/cilium/cilium/pkg/datapath"
	v1 "github.com/cilium/cilium/pkg/gke/apis/nodepool/v1"
	"github.com/cilium/cilium/pkg/gke/client/nodepool/clientset/versioned"
	"github.com/cilium/cilium/pkg/gke/client/nodepool/informers/externalversions"
	peertypes "github.com/cilium/cilium/pkg/hubble/peer/types"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/node/addressing"
	"github.com/cilium/cilium/pkg/node/manager"
	"github.com/cilium/cilium/pkg/node/types"
	"github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/tools/cache"
)

const informerSyncPeriod = 10 * time.Hour

type globalPeerNotifier struct {
	opts Options
	log  logrus.FieldLogger
	manager.Notifier
	nodePoolInformer cache.SharedIndexInformer

	// mux protects fields below
	mux      *lock.Mutex
	handlers []datapath.NodeHandler
	// nodes is a map of the node's k8s IP to the node itself.
	nodes map[string]types.Node
}

func newGlobalPeerNotifier(log logrus.FieldLogger) *globalPeerNotifier {
	return &globalPeerNotifier{
		log:   log,
		mux:   new(lock.Mutex),
		nodes: make(map[string]types.Node),
	}
}

// NewGlobalPeerNotifier returns a new instance of globalPeerNotifier which
// watches ABM NodePool custom resources. When change is detected it calls
// methods on registered handlers which are ongoing RPC requests to Hubble peer
// service.
func NewGlobalPeerNotifier(log logrus.FieldLogger, kc *versioned.Clientset, opts Options) (*globalPeerNotifier, error) {
	gp := newGlobalPeerNotifier(log)
	gp.opts = opts
	gp.log.Info("Starting Hubble Global Peer agent")

	nodePoolInformerFactory := externalversions.NewSharedInformerFactory(kc, informerSyncPeriod)
	gp.nodePoolInformer = nodePoolInformerFactory.Baremetal().V1().NodePools().Informer()

	gp.nodePoolInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    gp.nodePoolAdd,
		UpdateFunc: gp.nodePoolUpdate,
		DeleteFunc: gp.nodePoolDelete,
	})
	return gp, nil
}

// Run starts NodePoolInformer which watches NodePool custom resource.
func (gp *globalPeerNotifier) Run(ctx context.Context) {
	gp.nodePoolInformer.Run(ctx.Done())
}

func (gp *globalPeerNotifier) nodePoolAdd(obj interface{}) {
	np, ok := obj.(*v1.NodePool)
	if !ok {
		gp.log.WithField(
			"type", fmt.Sprintf("%T", obj),
		).Error("NodePool to add has an unexpected type")
		return
	}
	gp.log.WithField("NodePool.Spec", np.Spec).Debug("Processing NodePool add")

	gp.mux.Lock()
	defer gp.mux.Unlock()
	clusterName := np.Spec.ClusterName
	for _, node := range np.Spec.Nodes {
		addr := node.GetK8sIP()
		if old, exists := gp.nodes[addr]; exists {
			if old.Cluster == clusterName {
				// Node was already processed
				continue
			}
		}
		gp.addNode(clusterName, addr)
	}
}

func (gp *globalPeerNotifier) nodePoolUpdate(old, curr interface{}) {
	np, ok := curr.(*v1.NodePool)
	if !ok {
		gp.log.WithField(
			"type", fmt.Sprintf("%T", curr),
		).Error("New NodePool to update has an unexpected type")
		return
	}
	clusterName := np.Spec.ClusterName

	// Processing relies on internal state instead of contents of old NodePool.
	// Print warnings and keep processing.
	if onp, ok := old.(*v1.NodePool); ok {
		if clusterName != onp.Spec.ClusterName {
			gp.log.WithFields(logrus.Fields{
				"old": onp.Spec.ClusterName,
				"new": clusterName,
			}).Warn("Mismatched cluster names in node pool update")
		}
	} else {
		gp.log.WithField(
			"type", fmt.Sprintf("%T", curr),
		).Warn("Old NodePool to update has an unexpected type")
	}
	gp.log.WithField("NodePool.Spec", np.Spec).Debug("Processing NodePool update")

	// Convert slice of nodes from new version for fast checking by addr.
	after := nodeSliceToMap(np.Spec.Nodes)

	gp.mux.Lock()
	defer gp.mux.Unlock()

	deleted, added := 0, 0
	for addr, node := range gp.nodes {
		// Skip nodes that are not part of this Cluster.
		if node.Cluster != clusterName {
			continue
		}
		// Skip nodes which state didn't change.
		if after[addr] {
			continue
		}
		// Deleted node.
		gp.removeNode(clusterName, addr)
		deleted++
	}
	for addr := range after {
		// Skip nodes which were already added to the pool.
		if old, ok := gp.nodes[addr]; ok {
			if old.Cluster != clusterName {
				gp.log.WithFields(logrus.Fields{
					"nodeAddr":   addr,
					"oldCluster": old.Cluster,
					"newCluster": clusterName,
				}).Warnf("Ignoring entry duplicated across clusters")
			}
			continue
		}
		// New node.
		gp.addNode(clusterName, addr)
		added++
	}
	if deleted+added > 0 {
		gp.log.WithFields(logrus.Fields{
			"deleted": deleted,
			"added":   added,
		}).Info("Modified nodes during NodePool update")
	}
}

func nodeSliceToMap(nodes []v1.Node) map[string]bool {
	ret := make(map[string]bool)
	for _, node := range nodes {
		addr := node.GetK8sIP()
		ret[addr] = true
	}
	return ret
}

func (gp *globalPeerNotifier) nodePoolDelete(obj interface{}) {
	np, ok := obj.(*v1.NodePool)
	if !ok {
		gp.log.WithField(
			"type", fmt.Sprintf("%T", obj),
		).Error("NodePool to delete has an unexpected type")
		return
	}
	gp.log.WithField("NodePool.Spec", np.Spec).Debug("Processing NodePool delete")

	gp.mux.Lock()
	defer gp.mux.Unlock()
	deleted := 0
	for _, node := range np.Spec.Nodes {
		addr := node.GetK8sIP()
		if _, ok := gp.nodes[addr]; !ok {
			// Node was already processed
			continue
		}
		gp.removeNode(np.Spec.ClusterName, addr)
		deleted++
	}
	if deleted > 0 {
		gp.log.WithField("deleted", deleted).Info("Modified nodes during NodePool remove")
	}
}

func (gp *globalPeerNotifier) removeNode(clusterName, addr string) {
	delete(gp.nodes, addr)
	gp.log.WithField("nodeAddr", addr).Debug("Sending node delete to subscribers")
	for _, handler := range gp.handlers {
		handler.NodeDelete(v1ToNode(clusterName, addr))
	}
}

func v1ToNode(clusterName, addr string) types.Node {
	return types.Node{
		Name:    "node-" + addr,
		Cluster: clusterName,
		IPAddresses: []types.Address{{
			Type: addressing.NodeExternalIP,
			IP:   net.ParseIP(addr),
		}},
	}
}

func (gp *globalPeerNotifier) addNode(clusterName, addr string) {
	newNode := v1ToNode(clusterName, addr)
	gp.nodes[addr] = newNode

	gp.log.WithField("nodeAddr", addr).Debug("Sending node add to subscribers")
	for _, handler := range gp.handlers {
		handler.NodeAdd(newNode)
	}
}

// Subcribe registers handler which will be informed about current list of nodes
// and any future updates to it. It is a part of implementation of Notifier
// interface.
func (gp *globalPeerNotifier) Subscribe(nh datapath.NodeHandler) {
	gp.mux.Lock()
	defer gp.mux.Unlock()

	id := len(gp.handlers)
	gp.log.WithField("ID", id).Info("New subscriber")
	gp.handlers = append(gp.handlers, nh)

	gp.log.WithFields(logrus.Fields{
		"ID":        id,
		"nodeCount": len(gp.nodes),
	}).Info("Sending initial list of nodes to handler")
	for _, node := range gp.nodes {
		gp.log.WithFields(logrus.Fields{
			"ID":       id,
			"nodeName": node.Name,
		}).Debug("Sending initial node info to handler")
		nh.NodeAdd(node)
	}
}

// Unsubscribe unregisters handler. It is a part of implementation of Notifier
// interface.
func (gp *globalPeerNotifier) Unsubscribe(nh datapath.NodeHandler) {
	gp.mux.Lock()
	defer gp.mux.Unlock()

	for i, handler := range gp.handlers {
		if handler == nh {
			gp.handlers[i] = gp.handlers[len(gp.handlers)-1]
			gp.handlers[len(gp.handlers)-1] = nil
			gp.handlers = gp.handlers[:len(gp.handlers)-1]
			gp.log.WithFields(logrus.Fields{
				"subscriber":      i,
				"subscriberCount": len(gp.handlers),
			}).Info("Unsubscribed handler")
			return
		}
	}
	gp.log.WithField("handler", fmt.Sprintf("%#v", nh)).Warn("Called unsubscribe on handler not on the list")
}

func (gp *globalPeerNotifier) watchNotifications(ctx context.Context, peerClientBuilder peertypes.ClientBuilder) error {
	connectAndProcess := func(ctx context.Context) {
		cl, err := peerClientBuilder.Client(gp.opts.PeerTarget)
		if err != nil {
			gp.log.WithFields(logrus.Fields{
				"error":  err,
				"target": gp.opts.PeerTarget,
			}).Warn("Failed to create peer client for peers synchronization; will try again after the timeout has expired")
			return
		}
		defer cl.Close()
		gp.requestAndProcessNotifications(ctx, cl)
	}

	wait.UntilWithContext(ctx, connectAndProcess, gp.opts.RetryTimeout)
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("notify for peer change notification: %w", err)
	}
	return nil
}

func (gp *globalPeerNotifier) requestAndProcessNotifications(ctx context.Context, cl peertypes.Client) {
	client, err := cl.Notify(ctx, &peerpb.NotifyRequest{})
	if err != nil {
		gp.log.WithFields(logrus.Fields{
			"error":             err,
			"connectionTimeout": gp.opts.DialTimeout,
		}).Warn("Failed to create peer notify client for peers change notification; will try again after the timeout has expired")
		return
	}
	for {
		cn, err := client.Recv()
		if err != nil {
			gp.log.WithFields(logrus.Fields{
				"error":             err,
				"connectionTimeout": gp.opts.DialTimeout,
			}).Warn("Error while receiving peer change notification; will try again after the timeout has expired")
			return
		}
		gp.log.WithField("changeNotification", cn).Info("Received peer change notification")
		gp.processChangeNotification(cn)
	}
}

func (gp *globalPeerNotifier) processChangeNotification(cn *peerpb.ChangeNotification) {
	gp.mux.Lock()
	defer gp.mux.Unlock()

	p := peertypes.FromChangeNotification(cn)
	addr := p.Address.(*net.TCPAddr).IP.String()
	switch cn.GetType() {
	case peerpb.ChangeNotificationType_PEER_ADDED:
		if node, ok := gp.nodes[addr]; ok {
			// Nothing to do.
			gp.log.WithFields(logrus.Fields{
				"nodeAddr":    addr,
				"nodeName":    node.Name,
				"clusterName": node.Cluster,
			}).Info("Node with this address already exists")
			return
		}
		gp.addNode(gp.opts.ClusterName, addr)
	case peerpb.ChangeNotificationType_PEER_DELETED:
		if _, ok := gp.nodes[addr]; !ok {
			// Nothing to do.
			gp.log.WithField("nodeAddr", addr).Info("Node with this address already doesn't exist")
			return
		}
		gp.removeNode(gp.opts.ClusterName, addr)
	case peerpb.ChangeNotificationType_PEER_UPDATED:
		gp.log.WithField("nodeAddr", addr).Error("Unhandled PEER_UPDATE")
	}
}
