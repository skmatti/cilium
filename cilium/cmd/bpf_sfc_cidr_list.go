package cmd

import (
	"github.com/cilium/cilium/pkg/command"
	"github.com/cilium/cilium/pkg/common"
	"github.com/cilium/cilium/pkg/maps/sfc"
	"github.com/spf13/cobra"
)

const (
	sfcCidrTitle   = "CIDR"
	prefixLenTitle = "PREFIX LENGTH"
)

var bpfSFCCIDRListCmd = &cobra.Command{
	Use:     "list",
	Aliases: []string{"ls"},
	Short:   "List SFC CIDR entries",
	Run: func(cmd *cobra.Command, args []string) {
		common.RequireRootPrivilege("cilium bpf sfccidr list")

		sfcCIDRList := make(map[string][]string)
		if err := sfc.CIDRMap.Dump(sfcCIDRList); err != nil {
			Fatalf("Unable to dump contents of map: %s", err)
		}

		if command.OutputOption() {
			if err := command.PrintOutput(sfcCIDRList); err != nil {
				Fatalf("Unable to generate JSON output: %s", err)
			}
			return
		}

		TablePrinter(sfcCidrTitle, prefixLenTitle, sfcCIDRList)
	},
}

func init() {
	bpfSFCCIDRCmd.AddCommand(bpfSFCCIDRListCmd)
	command.AddOutputOption(bpfSFCCIDRListCmd)
}
