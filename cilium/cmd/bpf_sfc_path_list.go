package cmd

import (
	"github.com/cilium/cilium/pkg/command"
	"github.com/cilium/cilium/pkg/common"
	"github.com/cilium/cilium/pkg/maps/sfc"
	"github.com/spf13/cobra"
)

const (
	pathTitle      = "PATH"
	sfAddressTitle = "SERVICE FUNCTION ADDRESS"
)

var bpfSFCPathListCmd = &cobra.Command{
	Use:     "list",
	Aliases: []string{"ls"},
	Short:   "List service function path entries",
	Run: func(cmd *cobra.Command, args []string) {
		common.RequireRootPrivilege("cilium bpf sfcpath list")

		sfcPathList := make(map[string][]string)
		if err := sfc.PathMap.Dump(sfcPathList); err != nil {
			Fatalf("Unable to dump contents of map: %s", err)
		}

		if command.OutputOption() {
			if err := command.PrintOutput(sfcPathList); err != nil {
				Fatalf("Unable to generate JSON output: %s", err)
			}
			return
		}

		TablePrinter(pathTitle, sfAddressTitle, sfcPathList)
	},
}

func init() {
	bpfSFCPathCmd.AddCommand(bpfSFCPathListCmd)
	command.AddOutputOption(bpfSFCPathListCmd)
}
