package cmd

import (
	"fmt"
	"os"

	"github.com/cilium/cilium/pkg/command"
	"github.com/cilium/cilium/pkg/common"
	"github.com/cilium/cilium/pkg/maps/pip"

	"github.com/spf13/cobra"
)

var bpfPersistentIPRoutingListCmd = &cobra.Command{
	Use:     "list",
	Aliases: []string{"ls"},
	Short:   "List persistent IP routing entries",
	Run: func(cmd *cobra.Command, args []string) {
		common.RequireRootPrivilege("cilium bpf piprouting list")

		bpfPersistentIPRoutesList := make(map[string][]string)
		if err := pip.RoutingMap.Dump(bpfPersistentIPRoutesList); err != nil {
			Fatalf("error dumping contents of map: %s\n", err)
		}
		if command.OutputOption() {
			if err := command.PrintOutput(bpfPersistentIPRoutesList); err != nil {
				Fatalf("error getting output of map in JSON: %s\n", err)
			}
			return
		}

		if len(bpfPersistentIPRoutesList) == 0 {
			fmt.Fprint(os.Stderr, "No entries found.\n")
		} else {
			TablePrinter("CIDR", "Endpoint Info", bpfPersistentIPRoutesList)
		}
	},
}

func init() {
	bpfPersistentIPRoutingCmd.AddCommand(bpfPersistentIPRoutingListCmd)
	command.AddOutputOption(bpfPersistentIPRoutingListCmd)
}
