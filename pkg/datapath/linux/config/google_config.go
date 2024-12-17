package config

import (
	"fmt"
	"io"

	datapath "github.com/cilium/cilium/pkg/datapath/types"
)

// writeMultinicEndpointConfig writes endpoint configurations specifically for multinic endpoints.
func (h *HeaderfileWriter) writeMultinicEndpointConfig(w io.Writer, e datapath.EndpointConfiguration) error {
	if e.IsMultiNIC() {
		// MULTI_NIC_DEVICE_TYPE is injected as an integer here to explicitly
		// represent the type of devices. It is used in the datapath to differentiate
		// L2 vs L3 type devices, e.g. Macvlan/Macvtap vs veth type.
		// More details: pkg/endpoint/google_endpoint.go:GetDeviceTypeIndex()
		fmt.Fprintf(w, "#define MULTI_NIC_DEVICE_TYPE %d\n", e.GetDeviceTypeIndex())
	}
	return nil
}
