package ciliumendpointslice

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"k8s.io/apimachinery/pkg/runtime"
	k8sTesting "k8s.io/client-go/testing"

	"github.com/cilium/cilium/operator/k8s"
	tu "github.com/cilium/cilium/operator/pkg/ciliumendpointslice/testutils"
	pkgk8s "github.com/cilium/cilium/pkg/k8s"
	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	cilium_v2a1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/hive"
	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestReconcileCreateWithMultiNIC(t *testing.T) {
	var (
		r                   *reconciler
		fakeClient          k8sClient.FakeClientset
		ciliumEndpoint      resource.Resource[*cilium_v2.CiliumEndpoint]
		ciliumEndpointSlice resource.Resource[*cilium_v2a1.CiliumEndpointSlice]
		cesMetrics          *Metrics
	)
	m := newCESManagerFcfs(2, log).(*cesManagerFcfs)
	hive := hive.New(
		k8sClient.FakeClientCell,
		k8s.ResourcesCell,
		metrics.Metric(NewMetrics),
		cell.Invoke(func(
			c *k8sClient.FakeClientset,
			cep resource.Resource[*cilium_v2.CiliumEndpoint],
			ces resource.Resource[*cilium_v2a1.CiliumEndpointSlice],
			metrics *Metrics,
		) error {
			fakeClient = *c
			ciliumEndpoint = cep
			ciliumEndpointSlice = ces
			cesMetrics = metrics
			return nil
		}),
	)
	ctx := context.Background()
	tlog := hivetest.Logger(t)
	hive.Start(tlog, ctx)
	r = newReconciler(ctx, fakeClient.CiliumFakeClientset.CiliumV2alpha1(), m, log, ciliumEndpoint, ciliumEndpointSlice, cesMetrics)
	cepStore, _ := ciliumEndpoint.Store(ctx)

	var createdSlice *v2alpha1.CiliumEndpointSlice
	fakeClient.CiliumFakeClientset.PrependReactor("create", "*", func(action k8sTesting.Action) (handled bool, ret runtime.Object, err error) {
		pa := action.(k8sTesting.CreateAction)
		createdSlice = pa.GetObject().(*v2alpha1.CiliumEndpointSlice)
		return true, nil, nil
	})

	cep1 := createStoreMultiNICEndpoint("cep-mn", "ns", 1, "cep-mn", "1.1.1.1")
	cepStore.CacheStore().Add(cep1)
	cep2 := createStoreMultiNICEndpoint("cep-mn-eth1", "ns", 2, "cep-mn", "1.1.1.2")
	cepStore.CacheStore().Add(cep2)
	m.mapping.insertCES(NewCESName("ces1"), "ns")
	m.mapping.insertCEP(CEPName(pkgk8s.CEPKey(cep1, "ns")), NewCESName("ces1"))
	m.mapping.insertCEP(CEPName(pkgk8s.CEPKey(cep2, "ns")), NewCESName("ces1"))
	r.reconcileCES(NewCESName("ces1"))

	assert.Equal(t, "ces1", createdSlice.Name)
	assert.Equal(t, 2, len(createdSlice.Endpoints))
	assert.Equal(t, "ns", createdSlice.Namespace)
	eps := []string{createdSlice.Endpoints[0].Name, createdSlice.Endpoints[1].Name}
	if diff := cmp.Diff(eps, []string{"cep-mn", "cep-mn"}); diff != "" {
		t.Fatalf("got different CCEP (-got vs +want): %s", diff)
	}

	hive.Stop(tlog, ctx)
}

func createStoreMultiNICEndpoint(name string, namespace string, identity int64, podName, ipv4 string) *cilium_v2.CiliumEndpoint {
	cep := tu.CreateStoreEndpoint(name, namespace, identity)
	cep.OwnerReferences = []metav1.OwnerReference{
		{
			Kind: "Pod",
			Name: podName,
		},
	}
	cep.Status.Networking.Addressing = cilium_v2.AddressPairList{{IPV4: ipv4}}
	return cep
}
