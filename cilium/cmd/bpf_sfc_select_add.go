package cmd

import (
	"strconv"
	"strings"

	"github.com/cilium/cilium/pkg/common"
	"github.com/cilium/cilium/pkg/maps/sfc"
	"github.com/cilium/cilium/pkg/u8proto"
	"github.com/spf13/cobra"
)

var bpfSFCSelectAddCmd = &cobra.Command{
	Args:  cobra.ExactArgs(7),
	Use:   "add <endpoint id> <ingress/egress> <from cidr> <to cidr> <port>[/protocol] <spi> <si>",
	Short: "Add/update SFC traffic selector entry",
	Run: func(cmd *cobra.Command, args []string) {
		common.RequireRootPrivilege("cilium bpf sfcselect add")

		id := ParseEndpointID(args[0])
		isEgress := ParseIsEgress(args[1])
		srcCIDR := ParseCIDR(args[2])
		dstCIDR := ParseCIDR(args[3])
		port, protos := ParsePortProto(args[4])
		pathKey := ParsePath(args[5], args[6])

		for _, proto := range protos {
			selectKey := sfc.NewSelectKey(id, isEgress, *srcCIDR, *dstCIDR, port, proto)
			if err := sfc.SelectMap.Update(selectKey, pathKey); err != nil {
				Fatalf("Failed to update map: %v", err)
			}
		}
	},
}

func ParsePortProto(portProtoStr string) (uint16, []u8proto.U8proto) {
	var proto u8proto.U8proto
	pSplit := strings.Split(portProtoStr, "/")

	port, err := strconv.ParseUint(pSplit[0], 10, 16)
	if err != nil {
		Fatalf("Invalid port %q: %s", pSplit[0], err)
	}

	switch len(pSplit) {
	case 1:
		proto = u8proto.ANY
	case 2:
		protoStr := strings.ToUpper(pSplit[1])
		proto, err = u8proto.ParseProtocol(protoStr)
		if !sfc.SupportedProtocol(proto) {
			Fatalf("Unsupported protocol %q", protoStr)
		}
		if err != nil {
			Fatalf("Invalid protocol %q: %v", protoStr, err)
		}
	default:
		Fatalf("Invalid format %q. Should be <port>[/<protocol>]", portProtoStr)
	}
	protos := []u8proto.U8proto{}
	if proto == u8proto.ANY {
		for _, supportedProto := range sfc.SupportedProtocols {
			protos = append(protos, supportedProto)
		}
	} else {
		protos = append(protos, proto)
	}

	return uint16(port), protos
}

func init() {
	bpfSFCSelectCmd.AddCommand(bpfSFCSelectAddCmd)
}
