package cmd

import (
	"fmt"
	"os"

	"github.com/cilium/cilium/pkg/command"
	"github.com/cilium/cilium/pkg/common"
	"github.com/cilium/cilium/pkg/maps/multinicdev"

	"github.com/spf13/cobra"
)

const (
	multiNICDevListUsage = "List multinicdev entries.\n"
)

var bpfMultiNICDevListCmd = &cobra.Command{
	Use:     "list",
	Aliases: []string{"ls"},
	Short:   "List multinicdev entries",
	Long:    multiNICDevListUsage,
	Run: func(cmd *cobra.Command, args []string) {
		common.RequireRootPrivilege("cilium bpf multinicdev list")

		bpfMultiNICDevList := make(map[string][]string)
		if err := multinicdev.Map.Dump(bpfMultiNICDevList); err != nil {
			Fatalf("error dumping contents of map: %s\n", err)
		}

		if command.OutputOption() {
			if err := command.PrintOutput(bpfMultiNICDevList); err != nil {
				Fatalf("error getting output of map in JSON: %s\n", err)
			}
			return
		}

		if len(bpfMultiNICDevList) == 0 {
			fmt.Fprint(os.Stderr, "No entries found.\n")
		} else {
			TablePrinter("MAC", "Device Info", bpfMultiNICDevList)
		}
	},
}

func init() {
	bpfMultiNICDevCmd.AddCommand(bpfMultiNICDevListCmd)
	command.AddOutputOption(bpfMultiNICDevListCmd)
}
