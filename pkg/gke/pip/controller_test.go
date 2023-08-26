package pip

import (
	"testing"

	pipv1 "gke-internal.googlesource.com/anthos-networking/apis/v2/persistent-ip/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestNeedsUpdate(t *testing.T) {
	testCases := []struct {
		description string
		dpv2Ready1  metav1.Condition
		dpv2Ready2  metav1.Condition
		wantResp    bool
	}{
		{
			description: "equal fields in dpv2Ready condition should return false",
			dpv2Ready1: metav1.Condition{
				Type:               string(pipv1.IPRouteDPV2Ready),
				ObservedGeneration: 1,
				Message:            "dummyMessage",
				Status:             metav1.ConditionTrue,
			},
			dpv2Ready2: metav1.Condition{
				Type:               string(pipv1.IPRouteDPV2Ready),
				ObservedGeneration: 1,
				Message:            "dummyMessage",
				Status:             metav1.ConditionTrue,
			},
			wantResp: false,
		},
		{
			description: "unequal fields in dpv2Ready condition should return true",
			dpv2Ready1: metav1.Condition{
				Type:               string(pipv1.IPRouteDPV2Ready),
				ObservedGeneration: 1,
				Message:            "dummyMessage",
				Status:             metav1.ConditionTrue,
			},
			dpv2Ready2: metav1.Condition{
				Type:               string(pipv1.IPRouteDPV2Ready),
				ObservedGeneration: 1,
				Message:            "dummyMessage",
				Status:             metav1.ConditionFalse,
			},
			wantResp: true,
		},
	}
	r := GKEIPRouteReconciler{}
	for _, tc := range testCases {
		resp := r.needsUpdate(gkeIPRoute(tc.dpv2Ready1), gkeIPRoute(tc.dpv2Ready2))
		if resp != tc.wantResp {
			t.Fatalf("needsUpdate returned incorrect response, got: %t, want: %t", resp, tc.wantResp)
		}
	}
}

func gkeIPRoute(dpv2Ready metav1.Condition) *pipv1.GKEIPRoute {
	return &pipv1.GKEIPRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test",
		},
		Status: pipv1.GKEIPRouteStatus{
			Conditions: []metav1.Condition{dpv2Ready},
		},
	}
}
