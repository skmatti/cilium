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

package watchers

import (
	"context"
	"encoding/json"
	"sync"

	"github.com/cilium/cilium/pkg/k8s"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/informer"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/node/addressing"
	v1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/tools/cache"
)

var (
	k8sNodeInitOnce sync.Once
)

func StartSynchronizingWindowsNodes() {
	k8sNodeInitOnce.Do(func() {
		nodeOptsModifier := func(options *metav1.ListOptions) {
			options.LabelSelector = labels.Set(map[string]string{v1.LabelOSStable: "windows"}).String()
		}

		_, nodeController := informer.NewInformer(
			cache.NewFilteredListWatchFromClient(k8s.WatcherClient().CoreV1().RESTClient(),
				"nodes", v1.NamespaceAll,
				nodeOptsModifier,
			),
			&slim_corev1.Node{},
			0,
			cache.ResourceEventHandlerFuncs{
				AddFunc: func(obj interface{}) {
					if node := k8s.ObjToV1Node(obj); node != nil {
						cn := convertToCiliumNode(node)
						if _, err := k8s.CiliumClient().CiliumV2().CiliumNodes().Create(context.TODO(), cn, metav1.CreateOptions{}); err != nil {
							log.WithError(err).Warn("Unable to create CiliumNode resource")
						}
					}
				},
				UpdateFunc: func(oldObj, newObj interface{}) {
					if node := k8s.ObjToV1Node(newObj); node != nil {
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
						if _, err := k8s.CiliumClient().CiliumV2().CiliumNodes().Patch(context.TODO(), node.ObjectMeta.Name, types.JSONPatchType, specPatch, metav1.PatchOptions{}); err != nil {
							log.WithError(err).Warn("Unable to update CiliumNode resource")
						}
					}
				},
				DeleteFunc: func(obj interface{}) {
					if node := k8s.ObjToV1Node(obj); node != nil {
						if err := k8s.CiliumClient().CiliumV2().CiliumNodes().Delete(context.TODO(), node.ObjectMeta.Name, metav1.DeleteOptions{}); err != nil && !k8serrors.IsNotFound(err) {
							log.WithError(err).Warn("Unable to delete CiliumNode resource")
						}
					}
				},
			},
			nil,
		)

		go nodeController.Run(wait.NeverStop)
	})
}

func convertToCiliumNode(node *v1.Node) *ciliumv2.CiliumNode {
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
