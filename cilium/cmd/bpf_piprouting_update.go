package cmd

import (
	"fmt"
	"os"
	"strconv"

	"github.com/cilium/cilium/pkg/common"
	"github.com/cilium/cilium/pkg/maps/pip"
	"github.com/spf13/cobra"
)

var bpfPersistentIPRoutingUpdateCmd = &cobra.Command{
	Args:    cobra.ExactArgs(3),
	Use:     "update",
	Short:   "Update persistent IP routing entries",
	Aliases: []string{"add"},
	Run: func(cmd *cobra.Command, args []string) {
		common.RequireRootPrivilege("cilium bpf piprouting update <cidr> <ep_id> <ifindex>")

		cidr := ParseCIDR(args[0])
		epID, err := strconv.ParseUint(args[1], 10, 16)
		if err != nil {
			Fatalf("Unable to parse endpoint ID %q: %v", args[1], err)
		}
		ifindex, err := strconv.ParseUint(args[2], 10, 32)
		if err != nil {
			Fatalf("Unable to parse ifindex %q: %v", args[2], err)
		}
		key := pip.NewCIDRKey(*cidr)
		value := &pip.RoutingEntry{
			EndpointID: uint16(epID),
			IfIndex:    uint32(ifindex),
		}
		if err := pip.RoutingMap.Update(key, value); err != nil {
			fmt.Fprintf(os.Stderr, "error updating contents of map: %s\n", err)
			os.Exit(1)
		}
	},
}

func init() {
	bpfPersistentIPRoutingCmd.AddCommand(bpfPersistentIPRoutingUpdateCmd)
}
