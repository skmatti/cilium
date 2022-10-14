package cmd

import (
	"github.com/cilium/cilium/pkg/command"
	"github.com/cilium/cilium/pkg/common"
	"github.com/cilium/cilium/pkg/maps/sfc"
	"github.com/spf13/cobra"
)

const (
	selectorTitle = "SELECTOR"
)

var bpfSFCSelectListCmd = &cobra.Command{
	Use:     "list",
	Aliases: []string{"ls"},
	Short:   "List SFC traffic selector entries",
	Run: func(cmd *cobra.Command, args []string) {
		common.RequireRootPrivilege("cilium bpf sfcselect list")

		sfcSelectList := make(map[string][]string)
		if err := sfc.SelectMap.Dump(sfcSelectList); err != nil {
			Fatalf("Unable to dump contents of map: %s", err)
		}

		if command.OutputOption() {
			if err := command.PrintOutput(sfcSelectList); err != nil {
				Fatalf("Unable to generate JSON output: %s", err)
			}
			return
		}

		TablePrinter(selectorTitle, pathTitle, sfcSelectList)
	},
}

func init() {
	bpfSFCSelectCmd.AddCommand(bpfSFCSelectListCmd)
	command.AddOutputOption(bpfSFCSelectListCmd)
}
