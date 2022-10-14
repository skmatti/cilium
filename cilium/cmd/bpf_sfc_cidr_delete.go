package cmd

import (
	"github.com/cilium/cilium/pkg/common"
	"github.com/cilium/cilium/pkg/maps/sfc"
	"github.com/spf13/cobra"
)

var bpfSFCCIDRDeleteCmd = &cobra.Command{
	Args:  cobra.ExactArgs(4),
	Use:   "delete <endpoint id> <ingress/egress> <source/destination> <cidr>",
	Short: "Delete SFC CIDR entry",
	Run: func(cmd *cobra.Command, args []string) {
		common.RequireRootPrivilege("cilium bpf sfccidr delete")

		id := ParseEndpointID(args[0])
		isEgress := ParseIsEgress(args[1])
		isDst := ParseIsDst(args[2])
		cidr := ParseCIDR(args[3])

		cidrKey := sfc.NewCIDRKey(id, isEgress, isDst, *cidr)

		if err := sfc.CIDRMap.Delete(cidrKey); err != nil {
			Fatalf("Failed to update map: %v", err)
		}
	},
}

func init() {
	bpfSFCCIDRCmd.AddCommand(bpfSFCCIDRDeleteCmd)
}
