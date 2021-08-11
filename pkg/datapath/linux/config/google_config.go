package config

import (
	"fmt"
	"io"

	"github.com/cilium/cilium/pkg/datapath"
)

// writeMultinicEndpointConfig writes endpoint configurations specifically for multinic endpoints.
func (h *HeaderfileWriter) writeMultinicEndpointConfig(w io.Writer, e datapath.EndpointConfiguration) error {
	if e.IsMultiNIC() {
		fmt.Fprint(w, "#define IS_MULTI_NIC_DEVICE 1\n")
	}
	return nil
}
