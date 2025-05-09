// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package clustermesh

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"path"
	"strings"
	"sync"

	"github.com/cilium/hive/cell"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/tools/cache"

	cmk8s "github.com/cilium/cilium/clustermesh-apiserver/clustermesh/k8s"
	"github.com/cilium/cilium/clustermesh-apiserver/syncstate"
	"github.com/cilium/cilium/operator/watchers"
	operatorWatchers "github.com/cilium/cilium/operator/watchers"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	cmutils "github.com/cilium/cilium/pkg/clustermesh/utils"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/identity"
	identityCache "github.com/cilium/cilium/pkg/identity/cache"
	"github.com/cilium/cilium/pkg/ipcache"
	ciliumio "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/informer"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_labels "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/labels"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/selection"
	"github.com/cilium/cilium/pkg/k8s/types"
	"github.com/cilium/cilium/pkg/k8s/utils"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/kvstore/store"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/metrics"
	nodeStore "github.com/cilium/cilium/pkg/node/store"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/promise"
	"github.com/cilium/cilium/pkg/version"
	v1meta "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var (
	log             = logging.DefaultLogger.WithField(logfields.LogSubsys, "clustermesh-apiserver")
	namespaceCache  cache.Store
	syncMultiNicEPs bool
)

func NewCmd(h *hive.Hive) *cobra.Command {
	rootCmd := &cobra.Command{
		Use:   "clustermesh",
		Short: "Run ClusterMesh",
		Run: func(cmd *cobra.Command, args []string) {
			if err := h.Run(slog.Default()); err != nil {
				log.Fatal(err)
			}
		},
		PreRun: func(cmd *cobra.Command, args []string) {
			// Overwrite the metrics namespace with the one specific for the ClusterMesh API Server
			metrics.Namespace = metrics.CiliumClusterMeshAPIServerNamespace
			option.Config.Populate(h.Viper())
			if option.Config.Debug {
				log.Logger.SetLevel(logrus.DebugLevel)
			}
			option.LogRegisteredOptions(h.Viper(), log)
			log.Infof("Cilium ClusterMesh %s", version.Version)
		},
	}

	h.RegisterFlags(rootCmd.Flags())
	rootCmd.AddCommand(h.Command())
	return rootCmd
}

type parameters struct {
	cell.In

	ExternalWorkloadsConfig
	ClusterInfo       cmtypes.ClusterInfo
	GoogleClusterInfo cmtypes.GoogleClusterInfo
	Clientset         k8sClient.Clientset
	Resources         cmk8s.Resources
	BackendPromise    promise.Promise[kvstore.BackendOperations]
	StoreFactory      store.Factory
	SyncState         syncstate.SyncState
}

func registerHooks(lc cell.Lifecycle, params parameters) error {
	lc.Append(cell.Hook{
		OnStart: func(ctx cell.HookContext) error {
			if !params.Clientset.IsEnabled() {
				return errors.New("Kubernetes client not configured, cannot continue.")
			}

			backend, err := params.BackendPromise.Await(ctx)
			if err != nil {
				return err
			}

			startServer(ctx, params.ClusterInfo, params.GoogleClusterInfo, params.EnableExternalWorkloads, params.Clientset, backend, params.Resources, params.StoreFactory, params.SyncState)
			return nil
		},
	})
	return nil
}

type identitySynchronizer struct {
	store        store.SyncStore
	encoder      func([]byte) string
	syncCallback func(context.Context)
}

func newIdentitySynchronizer(ctx context.Context, cinfo cmtypes.ClusterInfo, backend kvstore.BackendOperations, factory store.Factory, syncCallback func(context.Context)) synchronizer {
	identitiesStore := factory.NewSyncStore(cinfo.Name, backend,
		path.Join(identityCache.IdentitiesPath, "id"),
		store.WSSWithSyncedKeyOverride(identityCache.IdentitiesPath))
	go identitiesStore.Run(ctx)

	return &identitySynchronizer{store: identitiesStore, encoder: backend.Encode, syncCallback: syncCallback}
}

func parseLabelArrayFromMap(base map[string]string) labels.LabelArray {
	array := make(labels.LabelArray, 0, len(base))
	for sourceAndKey, value := range base {
		array = append(array, labels.NewLabel(sourceAndKey, value, ""))
	}
	return array.Sort()
}

func (is *identitySynchronizer) upsert(ctx context.Context, _ resource.Key, obj runtime.Object) error {
	identity := obj.(*ciliumv2.CiliumIdentity)
	scopedLog := log.WithField(logfields.Identity, identity.Name)
	if len(identity.SecurityLabels) == 0 {
		scopedLog.WithError(errors.New("missing security labels")).Warning("Ignoring invalid identity")
		// Do not return an error, since it is pointless to retry.
		// We will receive a new update event if the security labels change.
		return nil
	}

	ns, err := getIdentityNamespace(identity)
	if err != nil {
		log.Warningf("Unable to get identity namespace: %v", err)
		return nil
	}

	if !shouldSync(ns) && !shouldSyncIdentity(identity) {
		log.Debugf("Not syncing identity from namespace %s", ns)
		return nil
	}

	labelArray := parseLabelArrayFromMap(identity.SecurityLabels)

	var labels []byte
	for _, l := range labelArray {
		labels = append(labels, l.FormatForKVStore()...)
	}

	scopedLog.Info("Upserting identity in etcd")
	kv := store.NewKVPair(identity.Name, is.encoder(labels))
	if err := is.store.UpsertKey(ctx, kv); err != nil {
		// The only errors surfaced by WorkqueueSyncStore are the unrecoverable ones.
		log.WithError(err).Warning("Unable to upsert identity in etcd")
	}

	return nil
}

func (is *identitySynchronizer) delete(ctx context.Context, key resource.Key) error {
	scopedLog := log.WithField(logfields.Identity, key.Name)
	scopedLog.Info("Deleting identity from etcd")

	if err := is.store.DeleteKey(ctx, store.NewKVPair(key.Name, "")); err != nil {
		// The only errors surfaced by WorkqueueSyncStore are the unrecoverable ones.
		scopedLog.WithError(err).Warning("Unable to delete node from etcd")
	}

	return nil
}

func (is *identitySynchronizer) synced(ctx context.Context) error {
	log.Info("Initial list of identities successfully received from Kubernetes")
	return is.store.Synced(ctx, is.syncCallback)
}

type nodeStub struct {
	cluster string
	name    string
}

func (n *nodeStub) GetKeyName() string {
	return nodeTypes.GetKeyNodeName(n.cluster, n.name)
}

type nodeSynchronizer struct {
	clusterInfo  cmtypes.ClusterInfo
	store        store.SyncStore
	syncCallback func(context.Context)
}

func newNodeSynchronizer(ctx context.Context, cinfo cmtypes.ClusterInfo, backend kvstore.BackendOperations, factory store.Factory, syncCallback func(context.Context)) synchronizer {
	nodesStore := factory.NewSyncStore(cinfo.Name, backend, nodeStore.NodeStorePrefix)
	go nodesStore.Run(ctx)

	return &nodeSynchronizer{clusterInfo: cinfo, store: nodesStore, syncCallback: syncCallback}
}

func (ns *nodeSynchronizer) upsert(ctx context.Context, _ resource.Key, obj runtime.Object) error {
	n := nodeTypes.ParseCiliumNode(obj.(*ciliumv2.CiliumNode))
	n.Cluster = ns.clusterInfo.Name
	n.ClusterID = ns.clusterInfo.ID

	scopedLog := log.WithField(logfields.Node, n.Name)
	scopedLog.Info("Upserting node in etcd")

	if err := ns.store.UpsertKey(ctx, &n); err != nil {
		// The only errors surfaced by WorkqueueSyncStore are the unrecoverable ones.
		log.WithError(err).Warning("Unable to upsert node in etcd")
	}

	return nil
}

func (ns *nodeSynchronizer) delete(ctx context.Context, key resource.Key) error {
	n := nodeStub{
		cluster: ns.clusterInfo.Name,
		name:    key.Name,
	}

	scopedLog := log.WithFields(logrus.Fields{logfields.Node: key.Name})
	scopedLog.Info("Deleting node from etcd")

	if err := ns.store.DeleteKey(ctx, &n); err != nil {
		// The only errors surfaced by WorkqueueSyncStore are the unrecoverable ones.
		scopedLog.WithError(err).Warning("Unable to delete node from etcd")
	}

	return nil
}

func (ns *nodeSynchronizer) synced(ctx context.Context) error {
	log.Info("Initial list of nodes successfully received from Kubernetes")
	return ns.store.Synced(ctx, ns.syncCallback)
}

type ipmap map[string]struct{}

type endpointSynchronizer struct {
	store        store.SyncStore
	cache        map[string]ipmap
	syncCallback func(context.Context)
}

func newEndpointSynchronizer(ctx context.Context, cinfo cmtypes.ClusterInfo, backend kvstore.BackendOperations, factory store.Factory, syncCallback func(context.Context)) synchronizer {
	endpointsStore := factory.NewSyncStore(cinfo.Name, backend,
		path.Join(ipcache.IPIdentitiesPath, ipcache.DefaultAddressSpace),
		store.WSSWithSyncedKeyOverride(ipcache.IPIdentitiesPath))
	go endpointsStore.Run(ctx)

	return &endpointSynchronizer{
		store:        endpointsStore,
		cache:        make(map[string]ipmap),
		syncCallback: syncCallback,
	}
}

func (es *endpointSynchronizer) upsert(ctx context.Context, key resource.Key, obj runtime.Object) error {
	endpoint := obj.(*types.CiliumEndpoint)
	if !shouldSync(endpoint.Namespace) && !shouldSyncCEP(endpoint) {
		log.Debugf("Not syncing endpoint from namespace %s", endpoint.Namespace)
		return nil
	}
	ips := make(ipmap)
	stale := es.cache[key.String()]

	if n := endpoint.Networking; n != nil {
		for _, address := range n.Addressing {
			for _, ip := range []string{address.IPV4, address.IPV6} {
				if ip == "" {
					continue
				}

				scopedLog := log.WithFields(logrus.Fields{logfields.Endpoint: key.String(), logfields.IPAddr: ip})
				entry := identity.IPIdentityPair{
					IP:           net.ParseIP(ip),
					HostIP:       net.ParseIP(n.NodeIP),
					K8sNamespace: endpoint.Namespace,
					K8sPodName:   endpoint.Name,
				}

				if endpoint.Identity != nil {
					entry.ID = identity.NumericIdentity(endpoint.Identity.ID)
				}

				if endpoint.Encryption != nil {
					entry.Key = uint8(endpoint.Encryption.Key)
				}

				scopedLog.Info("Upserting endpoint in etcd")
				if err := es.store.UpsertKey(ctx, &entry); err != nil {
					// The only errors surfaced by WorkqueueSyncStore are the unrecoverable ones.
					scopedLog.WithError(err).Warning("Unable to upsert endpoint in etcd")
					continue
				}

				ips[ip] = struct{}{}
				delete(stale, ip)
			}
		}
	}

	// Delete the stale endpoint IPs from the KVStore.
	es.deleteEndpoints(ctx, key, stale)
	es.cache[key.String()] = ips

	return nil
}

func (es *endpointSynchronizer) delete(ctx context.Context, key resource.Key) error {
	es.deleteEndpoints(ctx, key, es.cache[key.String()])
	delete(es.cache, key.String())
	return nil
}

func (es *endpointSynchronizer) synced(ctx context.Context) error {
	log.Info("Initial list of endpoints successfully received from Kubernetes")
	return es.store.Synced(ctx, es.syncCallback)
}

func (es *endpointSynchronizer) deleteEndpoints(ctx context.Context, key resource.Key, ips ipmap) {
	for ip := range ips {
		scopedLog := log.WithFields(logrus.Fields{logfields.Endpoint: key.String(), logfields.IPAddr: ip})
		scopedLog.Info("Deleting endpoint from etcd")

		entry := identity.IPIdentityPair{IP: net.ParseIP(ip)}
		if err := es.store.DeleteKey(ctx, &entry); err != nil {
			// The only errors surfaced by WorkqueueSyncStore are the unrecoverable ones.
			scopedLog.WithError(err).Warning("Unable to delete endpoint from etcd")
		}
	}
}

type synchronizer interface {
	upsert(ctx context.Context, key resource.Key, obj runtime.Object) error
	delete(ctx context.Context, key resource.Key) error
	synced(ctx context.Context) error
}

func synchronize[T runtime.Object](ctx context.Context, r resource.Resource[T], sync synchronizer) {
	for event := range r.Events(ctx) {
		switch event.Kind {
		case resource.Upsert:
			event.Done(sync.upsert(ctx, event.Key, event.Object))
		case resource.Delete:
			event.Done(sync.delete(ctx, event.Key))
		case resource.Sync:
			event.Done(sync.synced(ctx))
		}
	}
}

func startServer(
	startCtx cell.HookContext,
	cinfo cmtypes.ClusterInfo,
	ginfo cmtypes.GoogleClusterInfo,
	allServices bool,
	clientset k8sClient.Clientset,
	backend kvstore.BackendOperations,
	resources cmk8s.Resources,
	factory store.Factory,
	syncState syncstate.SyncState,
) {
	log.WithFields(logrus.Fields{
		"cluster-name": cinfo.Name,
		"cluster-id":   cinfo.ID,
	}).Info("Starting clustermesh-apiserver...")

	config := cmtypes.CiliumClusterConfig{
		ID: cinfo.ID,
		Capabilities: cmtypes.CiliumClusterConfigCapabilities{
			SyncedCanaries:       true,
			MaxConnectedClusters: cinfo.MaxConnectedClusters,
		},
	}

	syncMultiNicEPs = ginfo.SyncMultiNicEPs

	_, err := cmutils.EnforceClusterConfig(context.Background(), cinfo.Name, config, backend, log)
	if err != nil {
		log.WithError(err).Fatal("Unable to set local cluster config on kvstore")
	}

	ctx := context.Background()

	// We only need to watch namespaces if some label restrictions are configured.
	// Otherwise we sync everything.
	if len(ginfo.NamespaceLabels) > 0 {
		if err := watchNamespaces(clientset, ginfo.NamespaceLabels); err != nil {
			log.WithError(err).Fatal("Unable to watch namespaces")
		}
	}

	go synchronize(ctx, resources.CiliumIdentities, newIdentitySynchronizer(ctx, cinfo, backend, factory, syncState.WaitForResource()))
	if !ginfo.DisableClustermeshNodeSync {
		go synchronize(ctx, resources.CiliumNodes, newNodeSynchronizer(ctx, cinfo, backend, factory, syncState.WaitForResource()))
	}
	go synchronize(ctx, resources.CiliumSlimEndpoints, newEndpointSynchronizer(ctx, cinfo, backend, factory, syncState.WaitForResource()))

	watchers.K8sSvcCache.UseIngressAsFEIP = true
	operatorWatchers.StartSynchronizingServices(ctx, &sync.WaitGroup{}, operatorWatchers.ServiceSyncParameters{
		ClusterInfo:   cinfo,
		Clientset:     clientset,
		Services:      resources.Services,
		Endpoints:     resources.Endpoints,
		Backend:       backend,
		SharedOnly:    !allServices,
		StoreFactory:  factory,
		SyncCallback:  syncState.WaitForResource(),
		SyncPredicate: shouldSync,
	})
	syncState.Stop()

	log.Info("Initialization complete")
}

func watchNamespaces(clientset k8sClient.Clientset, labels []string) error {
	labelSelector, err := buildLabelSelector(labels)
	if err != nil {
		return fmt.Errorf("unable to build label selector: %v", err)
	}

	modifier := func(options *v1meta.ListOptions) {
		options.LabelSelector = labelSelector.String()
	}

	namespaceStore, namespaceInformer := informer.NewInformer(
		utils.ListerWatcherWithModifier(
			utils.ListerWatcherFromTyped[*slim_corev1.NamespaceList](clientset.Slim().CoreV1().Namespaces()), modifier),
		&slim_corev1.Namespace{},
		0,
		cache.ResourceEventHandlerFuncs{},
		nil,
	)
	namespaceCache = namespaceStore

	go namespaceInformer.Run(wait.NeverStop)
	if ok := cache.WaitForNamedCacheSync("clustermesh-apiserver", wait.NeverStop, namespaceInformer.HasSynced); !ok {
		return fmt.Errorf("failed to wait for namespace cache to sync")
	}

	return nil
}

func buildLabelSelector(labels []string) (slim_labels.Selector, error) {
	labelSelector := slim_labels.NewSelector()

	for _, label := range labels {
		labelNameSelector, err := slim_labels.NewRequirement(
			label, selection.Exists, nil)

		if err != nil {
			return nil, err
		}

		labelSelector = labelSelector.Add(*labelNameSelector)
	}

	return labelSelector, nil
}

func getIdentityNamespace(identity *ciliumv2.CiliumIdentity) (string, error) {
	l := strings.TrimSuffix(labels.GenerateK8sLabelString(ciliumio.PodNamespaceLabel, ""), "=")

	ns, found := identity.SecurityLabels[l]
	if !found {
		return "", fmt.Errorf("no namespace label found on identity %q", identity.Name)
	}

	return ns, nil
}

var shouldSync = func(namespace string) bool {
	if namespaceCache == nil {
		return true
	}

	nsName := &slim_corev1.Namespace{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name: namespace,
		},
	}
	_, exists, err := namespaceCache.Get(nsName)
	if err != nil {
		log.WithError(err).Errorf("unable to get namespace %q from cache", nsName)
		return false
	}

	return exists
}
