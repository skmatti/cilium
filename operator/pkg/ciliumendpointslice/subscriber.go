package ciliumendpointslice

import capi_v2a1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"

var (
	cesAddHandlers    []func(ces *capi_v2a1.CiliumEndpointSlice)
	cesUpdateHandlers []func(ces *capi_v2a1.CiliumEndpointSlice)
	cesDeleteHandlers []func(ces *capi_v2a1.CiliumEndpointSlice)
)

func processCESAdd(ces *capi_v2a1.CiliumEndpointSlice) {
	for _, f := range cesAddHandlers {
		f(ces)
	}
}

func processCESUpdate(ces *capi_v2a1.CiliumEndpointSlice) {
	for _, f := range cesUpdateHandlers {
		f(ces)
	}
}
func processCESDelete(ces *capi_v2a1.CiliumEndpointSlice) {
	for _, f := range cesDeleteHandlers {
		f(ces)
	}
}

func SubscribeToCESAddEvent(f func(ces *capi_v2a1.CiliumEndpointSlice)) {
	cesAddHandlers = append(cesAddHandlers, f)
}

func SubscribeToCESUpdateEvent(f func(ces *capi_v2a1.CiliumEndpointSlice)) {
	cesUpdateHandlers = append(cesUpdateHandlers, f)
}

func SubscribeToCESDeleteEvent(f func(ces *capi_v2a1.CiliumEndpointSlice)) {
	cesDeleteHandlers = append(cesDeleteHandlers, f)
}
