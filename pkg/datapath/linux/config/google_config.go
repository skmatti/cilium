package config

import (
	"bytes"
	"fmt"
	"io"
	"text/template"

	"github.com/cilium/cilium/pkg/byteorder"
	"github.com/cilium/cilium/pkg/datapath"
	"github.com/cilium/cilium/pkg/datapath/link"
	"github.com/cilium/cilium/pkg/node"
)

// writeMultinicEndpointConfig writes endpoint configurations specifically for multinic endpoints.
func (h *HeaderfileWriter) writeMultinicEndpointConfig(w io.Writer, e datapath.EndpointConfiguration) error {
	if e.IsMultiNIC() {
		fmt.Fprint(w, "#define IS_MULTI_NIC_DEVICE 1\n")
	}
	return nil
}

func nodePortIPv4AddrsMacro() (string, error) {
	var macro bytes.Buffer
	ips := make(map[int]string)
	for iface, ip := range node.GetNodePortIPv4AddrsWithDevices() {
		idx, err := link.GetIfIndex(iface)
		if err != nil {
			return "", err
		}
		ip := byteorder.NetIPv4ToHost32(ip)
		ips[int(idx)] = fmt.Sprintf("%d", ip)
	}

	tmpl := template.Must(template.New("nodePortIPv4ByIfIndex").Parse(
		`({ \
__be32 __ip = 0; \
switch (IFINDEX) { \
{{range $idx,$ip := .}} case {{$idx}}: __ip={{$ip}}; break; \
{{end}}} \
__ip; })`))
	if err := tmpl.Execute(&macro, ips); err != nil {
		return "", fmt.Errorf("failed to execute template: %q", err)
	}
	return macro.String(), nil
}
