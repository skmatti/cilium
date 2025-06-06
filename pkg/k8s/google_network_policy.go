package k8s

import (
	"github.com/cilium/cilium/pkg/gke/features"
	k8sConst "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	slim_networkingv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/networking/v1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
)

// applyLocalClusterScope scopes a network policy peer to the local cluster by adding a PodSelector label,
// if the GoogleRestrictK8sNPScopeToLocalCluster flag is enabled.
func applyLocalClusterScope(peer *slim_networkingv1.NetworkPolicyPeer, namespace string) {
	if !features.GlobalConfig.GoogleRestrictK8sNPScopeToLocalCluster {
		return
	}

	if peer.NamespaceSelector == nil && peer.PodSelector == nil {
		return
	}

	currentClusterName := option.Config.ClusterName
	if currentClusterName == "" {
		log.WithField(logfields.K8sNamespace, namespace).
			Warningf("K8s NetworkPolicy scope restriction is enabled but ClusterName is empty")
		return
	}

	// Ensure PodSelector exists to add the cluster label.
	if peer.PodSelector == nil {
		peer.PodSelector = &slim_metav1.LabelSelector{}
	}
	if peer.PodSelector.MatchLabels == nil {
		peer.PodSelector.MatchLabels = make(map[string]string)
	}
	// Add local cluster label to the PodSelector for this peer.
	peer.PodSelector.MatchLabels[k8sConst.PolicyLabelCluster] = currentClusterName
}
