package cmd

import (
	"github.com/cilium/cilium/pkg/common"
	"github.com/cilium/cilium/pkg/maps/pip"
	"github.com/spf13/cobra"
)

var bpfPersistentIPRoutingDeleteCmd = &cobra.Command{
	Args:  cobra.ExactArgs(1),
	Use:   "delete",
	Short: "Delete persistent IP routing entries",
	Run: func(cmd *cobra.Command, args []string) {
		common.RequireRootPrivilege("cilium bpf piprouting delete <cidr>")

		cidr := ParseCIDR(args[0])
		key := pip.NewCIDRKey(*cidr)
		if err := pip.RoutingMap.Delete(key); err != nil {
			Fatalf("error deleting contents of map: %s\n", err)
		}
	},
}

func init() {
	bpfPersistentIPRoutingCmd.AddCommand(bpfPersistentIPRoutingDeleteCmd)
}
