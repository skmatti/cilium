package hostfirewall

import (
	"context"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sclient "sigs.k8s.io/controller-runtime/pkg/client"

	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	ciliumlabels "github.com/cilium/cilium/pkg/labels"
	ciliumapi "github.com/cilium/cilium/pkg/policy/api"

	"gke-internal.googlesource.com/third_party/cilium/google_test/wora/e2e/pkg/test/utils"
	"k8s.io/client-go/rest"
)

func applyCCNPWithIngressPolicy(cl k8sclient.Client, policyName string, nodeSelectorIP string, ingressLabelKey string, ingressLabelValue string) error {
	// Cilium Clusterwide NetworkPolicy object
	ccnp := &ciliumv2.CiliumClusterwideNetworkPolicy{
		TypeMeta: metav1.TypeMeta{
			APIVersion: ciliumv2.SchemeGroupVersion.String(),
			Kind:       ciliumv2.CCNPKindDefinition,
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: policyName,
		},
		Spec: &ciliumapi.Rule{
			NodeSelector: ciliumapi.NewESFromK8sLabelSelector(
				ciliumlabels.LabelSourceK8sKeyPrefix, &slim_metav1.LabelSelector{
					MatchLabels: map[string]string{
						"baremetal.cluster.gke.io/k8s-ip": nodeSelectorIP,
					},
				},
			),
			Ingress: []ciliumapi.IngressRule{
				{
					IngressCommonRule: ciliumapi.IngressCommonRule{
						FromEntities: ciliumapi.EntitySlice{
							ciliumapi.EntityKubeAPIServer,
							ciliumapi.EntityHealth,
							ciliumapi.EntityWorld,
							ciliumapi.EntityHost,
							ciliumapi.EntityRemoteNode,
						},
					},
				},
				{
					IngressCommonRule: ciliumapi.IngressCommonRule{
						FromEndpoints: []ciliumapi.EndpointSelector{
							ciliumapi.NewESFromK8sLabelSelector(
								ciliumlabels.LabelSourceK8sKeyPrefix, &slim_metav1.LabelSelector{
									MatchLabels: map[string]string{
										ingressLabelKey: ingressLabelValue,
									},
								},
							),
						},
					},
				},
			},
		},
	}
	err := cl.Create(context.Background(), ccnp)
	return err
}

func deleteCCNP(cl k8sclient.Client, config *rest.Config, ccnpName string) error {
	err := cl.Delete(context.Background(), &ciliumv2.CiliumClusterwideNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name: ccnpName,
		},
	})
	return err
}

func deleteAndWaitForPodDeletion(ctx context.Context, cl k8sclient.Client, podName, namespace string) error {
	utils.DeletePod(ctx, cl, podName, namespace)
	err := utils.WaitForPodDeletion(ctx, cl, podName, namespace)
	return err
}
