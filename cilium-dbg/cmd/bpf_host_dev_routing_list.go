package cmd

import (
	"fmt"
	"os"

	"github.com/cilium/cilium/pkg/command"
	"github.com/cilium/cilium/pkg/common"
	"github.com/cilium/cilium/pkg/maps/multinetworking"

	"github.com/spf13/cobra"
)

var bpfHostDeviceRoutingListCmd = &cobra.Command{
	Use:     "list",
	Aliases: []string{"ls"},
	Short:   "List host device bpf routing entries",
	Run: func(cmd *cobra.Command, args []string) {
		common.RequireRootPrivilege("cilium bpf hostdevrouting list")

		bpfHostDeviceRoutingList := make(map[string][]string)
		if err := multinetworking.HostDevRoutingMap.Dump(bpfHostDeviceRoutingList); err != nil {
			Fatalf("error dumping contents of map: %s\n", err)
		}
		if command.OutputOption() {
			if err := command.PrintOutput(bpfHostDeviceRoutingList); err != nil {
				Fatalf("error getting output of map in JSON: %s\n", err)
			}
			return
		}

		if len(bpfHostDeviceRoutingList) == 0 {
			fmt.Fprint(os.Stderr, "No entries found.\n")
		} else {
			TablePrinter("IfIndex/CIDR", "NextHopAddr", bpfHostDeviceRoutingList)
		}
	},
}

func init() {
	bpfHostDevRoutingCmd.AddCommand(bpfHostDeviceRoutingListCmd)
	command.AddOutputOption(bpfHostDeviceRoutingListCmd)
}
