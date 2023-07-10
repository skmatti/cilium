package cmd

import (
	"fmt"
	"net"
	"os"

	"github.com/cilium/cilium/pkg/common"
	"github.com/cilium/cilium/pkg/maps/pip"
	"github.com/spf13/cobra"
)

var bpfPersistentIPRoutingUpdateCmd = &cobra.Command{
	Args:    cobra.ExactArgs(2),
	Use:     "update <cidr> <ep_ip>",
	Short:   "Update persistent IP routing entries",
	Aliases: []string{"add"},
	Run: func(cmd *cobra.Command, args []string) {
		common.RequireRootPrivilege("cilium bpf piprouting update")

		cidr := ParseCIDR(args[0])
		epIP := net.ParseIP(args[1])
		if epIP == nil {
			Fatalf("Unable to parse endpoint IP %q", args[1])
		}
		key := pip.NewCIDRKey(cidr)
		value := pip.NewRoutingEntry(epIP)
		if key.Family != value.Family {
			Fatalf("IP Family must match in key and value: %d != %d", key.Family, value.Family)
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
