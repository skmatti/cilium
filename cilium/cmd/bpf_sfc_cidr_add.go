package cmd

import (
	"net"
	"strconv"

	"github.com/cilium/cilium/pkg/common"
	"github.com/cilium/cilium/pkg/maps/sfc"
	"github.com/spf13/cobra"
)

var bpfSFCCIDRAddCmd = &cobra.Command{
	Args:  cobra.ExactArgs(4),
	Use:   "add <endpoint id> <ingress/egress> <source/destination> <cidr>",
	Short: "Add/update SFC CIDR entry",
	Run: func(cmd *cobra.Command, args []string) {
		common.RequireRootPrivilege("cilium bpf sfccidr add")

		id := ParseEndpointID(args[0])
		isEgress := ParseIsEgress(args[1])
		isDst := ParseIsDst(args[2])
		cidr := ParseCIDR(args[3])

		cidrKey := sfc.NewCIDRKey(id, isEgress, isDst, *cidr)
		cidrEntry := sfc.NewCIDREntry(*cidr)

		if err := sfc.CIDRMap.Update(cidrKey, cidrEntry); err != nil {
			Fatalf("Failed to update map: %v", err)
		}
	},
}

func ParseEndpointID(idStr string) uint16 {
	id, err := strconv.ParseUint(idStr, 10, 16)
	if err != nil {
		Fatalf("Unable to parse endpointID %q: %v", idStr, err)
	}
	return uint16(id)
}

func ParseIsEgress(dir string) bool {
	switch dir {
	case "ingress":
		return false
	case "egress":
		return true
	}
	Fatalf("Unable to parse <ingress/egress> %q", dir)
	// unreachable
	return false
}

func ParseIsDst(dir string) bool {
	switch dir {
	case "source", "src":
		return false
	case "destination", "dst":
		return true
	}
	Fatalf("Unable to parse <source/destination> %q", dir)
	// unreachable
	return false
}

func ParseCIDR(cidrStr string) *net.IPNet {
	_, cidr, err := net.ParseCIDR(cidrStr)
	if err != nil {
		Fatalf("Unable to parse CIDR %q: %v", cidrStr, err)
	}
	return cidr
}

func init() {
	bpfSFCCIDRCmd.AddCommand(bpfSFCCIDRAddCmd)
}
