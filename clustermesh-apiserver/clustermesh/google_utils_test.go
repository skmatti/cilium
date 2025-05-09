package clustermesh

import (
	"testing"

	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestShouldSyncIdentity(t *testing.T) {
	regularIdentity := &v2.CiliumIdentity{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "ep",
			Namespace: "default",
		},
		SecurityLabels: map[string]string{
			"k8s:networking.gke.io/network": "default",
		},
	}
	multinicIdentity := &v2.CiliumIdentity{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "ep",
			Namespace: "default",
		},
		SecurityLabels: map[string]string{
			"k8s:networking.gke.io/network": "secondary",
		},
	}
	testCases := []struct {
		identity           *v2.CiliumIdentity
		enableMultiNicSync bool
		want               bool
	}{
		{
			identity:           regularIdentity,
			enableMultiNicSync: false,
			want:               false,
		},
		{
			identity:           regularIdentity,
			enableMultiNicSync: true,
			want:               false,
		},
		{
			identity:           multinicIdentity,
			enableMultiNicSync: false,
			want:               false,
		},
		{
			identity:           multinicIdentity,
			enableMultiNicSync: true,
			want:               true,
		},
	}
	for _, tc := range testCases {
		syncMultiNicEPs = tc.enableMultiNicSync
		res := shouldSyncIdentity(tc.identity)
		if res != tc.want {
			t.Errorf("result did not match expected: got=%t, want=%t", res, tc.want)
		}
	}
}
