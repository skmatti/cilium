// Copyright 2016-2020 Authors of Cilium
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

package windows

import (
	"context"
	"encoding/json"

	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/k8s"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/informer"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/node/addressing"
	v1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/cache"
)

var (
	log = logging.DefaultLogger.WithField(logfields.LogSubsys, "windows")
)

func startSynchronizingWindowsNodes(config Config, clientset k8sClient.Clientset, lc hive.Lifecycle) {
	if !config.SynchronizeK8sWindowsNodes {
		return
	}

	nodeOptsModifier := func(options *metav1.ListOptions) {
		options.LabelSelector = labels.Set(map[string]string{v1.LabelOSStable: "windows"}).String()
	}

	_, nodeController := informer.NewInformer(
		cache.NewFilteredListWatchFromClient(clientset.CoreV1().RESTClient(),
			"nodes", v1.NamespaceAll,
			nodeOptsModifier,
		),
		&slim_corev1.Node{},
		0,
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				if node := objToSlimV1Node(obj); node != nil {
					cn := convertToCiliumNode(node)
					if _, err := clientset.CiliumV2().CiliumNodes().Create(context.TODO(), cn, metav1.CreateOptions{}); err != nil {
						log.WithError(err).Warn("Unable to create CiliumNode resource")
					}
				}
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				if node := objToSlimV1Node(newObj); node != nil {
					cn := convertToCiliumNode(node)
					replaceCNSpec := []k8s.JSONPatch{
						{
							OP:    "replace",
							Path:  "/spec",
							Value: cn.Spec,
						},
					}
					specPatch, err := json.Marshal(replaceCNSpec)
					if err != nil {
						log.WithError(err).Warn("Unable to create a Patch")
						return
					}
					if _, err := clientset.CiliumV2().CiliumNodes().Patch(context.TODO(), node.ObjectMeta.Name, types.JSONPatchType, specPatch, metav1.PatchOptions{}); err != nil {
						log.WithError(err).Warn("Unable to update CiliumNode resource")
					}
				}
			},
			DeleteFunc: func(obj interface{}) {
				if node := objToSlimV1Node(obj); node != nil {
					if err := clientset.CiliumV2().CiliumNodes().Delete(context.TODO(), node.ObjectMeta.Name, metav1.DeleteOptions{}); err != nil && !k8serrors.IsNotFound(err) {
						log.WithError(err).Warn("Unable to delete CiliumNode resource")
					}
				}
			},
		},
		nil,
	)

	stopChan := make(chan struct{})
	lc.Append(hive.Hook{
		OnStart: func(_ hive.HookContext) error {
			nodeController.Run(stopChan)
			return nil
		},
		OnStop: func(_ hive.HookContext) error {
			close(stopChan)
			return nil
		},
	})
}

func convertToCiliumNode(node *slim_corev1.Node) *ciliumv2.CiliumNode {
	cn := &ciliumv2.CiliumNode{
		ObjectMeta: metav1.ObjectMeta{
			Name: node.ObjectMeta.Name,
		},
	}

	cn.Spec.Addresses = []ciliumv2.NodeAddress{}
	for _, addr := range node.Status.Addresses {
		addrType := addressing.AddressType(addr.Type)
		switch addrType {
		case addressing.NodeExternalIP, addressing.NodeInternalIP:
		default:
			continue
		}

		if addr.Address == "" {
			continue
		}

		na := ciliumv2.NodeAddress{
			Type: addrType,
			IP:   addr.Address,
		}
		cn.Spec.Addresses = append(cn.Spec.Addresses, na)
	}
	cn.Spec.IPAM.PodCIDRs = []string{node.Spec.PodCIDR}

	return cn
}

func objToSlimV1Node(obj interface{}) *slim_corev1.Node {
	node, ok := obj.(*slim_corev1.Node)
	if ok {
		return node
	}
	deletedObj, ok := obj.(cache.DeletedFinalStateUnknown)
	if ok {
		// Delete was not observed by the watcher but is
		// removed from kube-apiserver. This is the last
		// known state and the object no longer exists.
		node, ok := deletedObj.Obj.(*slim_corev1.Node)
		if ok {
			return node
		}
	}
	log.WithField(logfields.Object, logfields.Repr(obj)).
		Warn("Ignoring invalid k8s v1 Node")
	return nil
}
