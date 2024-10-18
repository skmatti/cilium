package cmd

import (
	"fmt"
	"os"
	"strconv"

	"github.com/cilium/cilium/pkg/common"
	"github.com/cilium/cilium/pkg/maps/multinetworking"
	"github.com/spf13/cobra"
)

var bpfHostDevRoutingDeleteCmd = &cobra.Command{
	Args:  cobra.ExactArgs(1),
	Use:   "delete <cidr> <ifindex>",
	Short: "Delete host device bpf routing entries",
	Run: func(cmd *cobra.Command, args []string) {
		common.RequireRootPrivilege("cilium bpf hostdevrouting delete")

		cidr := ParseCIDR(args[0])
		ifIndex, err := strconv.Atoi(args[1])
		if err != nil {
			fmt.Fprintf(os.Stderr, "could not parse ifindex: %s\n", err)
			os.Exit(1)
		}
		key := multinetworking.NewHostDevRoutingKey(uint32(ifIndex), cidr)
		if err := multinetworking.HostDevRoutingMap.Delete(key); err != nil {
			Fatalf("error deleting contents of map: %s\n", err)
		}
	},
}

func init() {
	bpfHostDevRoutingCmd.AddCommand(bpfHostDevRoutingDeleteCmd)
}
