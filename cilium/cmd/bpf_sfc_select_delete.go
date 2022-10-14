package cmd

import (
	"github.com/cilium/cilium/pkg/common"
	"github.com/cilium/cilium/pkg/maps/sfc"
	"github.com/spf13/cobra"
)

var bpfSFCSelectDeleteCmd = &cobra.Command{
	Args:  cobra.ExactArgs(5),
	Use:   "delete <endpoint id> <ingress/egress> <from cidr> <to cidr> <port>[/protocol]",
	Short: "Delete SFC traffic selector entry",
	Run: func(cmd *cobra.Command, args []string) {
		common.RequireRootPrivilege("cilium bpf sfcselect delete")

		id := ParseEndpointID(args[0])
		isEgress := ParseIsEgress(args[1])
		srcCIDR := ParseCIDR(args[2])
		dstCIDR := ParseCIDR(args[3])
		port, protos := ParsePortProto(args[4])

		for _, proto := range protos {
			selectKey := sfc.NewSelectKey(id, isEgress, *srcCIDR, *dstCIDR, port, proto)
			if err := sfc.SelectMap.Delete(selectKey); err != nil {
				Fatalf("Failed to update map: %v", err)
			}
		}
	},
}

func init() {
	bpfSFCSelectCmd.AddCommand(bpfSFCSelectDeleteCmd)
}
